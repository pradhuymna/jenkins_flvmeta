#include "ffmpeg.h"
#include "motion.h"

#if (defined(BSD) && !defined(PWCBSD))
#include "video_freebsd.h"
#else
#include "video.h"
#endif /* BSD */

#include "conf.h"
#include "alg.h"
#include "track.h"
#include "event.h"
#include "picture.h"
#include "rotate.h"

/* Forward declarations */
static int motion_init(struct context *cnt);
static void motion_cleanup(struct context *cnt);

pthread_key_t tls_key_threadnr;
pthread_mutex_t global_lock;
struct context **cnt_list = NULL;
volatile int threads_running = 0;
unsigned short int debug_level;
volatile unsigned short int finish = 0;

unsigned short int restart = 0;
void event_stop_webcam(struct context *cnt, int type ATTRIBUTE_UNUSED,
            unsigned char *dummy1 ATTRIBUTE_UNUSED,
            char *dummy2 ATTRIBUTE_UNUSED, void *dummy3 ATTRIBUTE_UNUSED,
            struct tm *tm ATTRIBUTE_UNUSED);

static void image_ring_resize(struct context *cnt, int new_size)
{
	/* Only resize if :
	 * Not in an event and
	 * decreasing at last position in new buffer
	 * increasing at last position in old buffer 
	 * e.g. at end of smallest buffer */
	if (cnt->event_nr != cnt->prev_event) {
		int smallest;

		if (new_size < cnt->imgs.image_ring_size) { /* Decreasing */
			smallest = new_size;
		} else { /* Increasing */
			smallest = cnt->imgs.image_ring_size;
		}

		if (cnt->imgs.image_ring_in == smallest - 1 || smallest == 0) {
			motion_log(LOG_INFO, 0, "Resizing pre_capture buffer to %d items", new_size);

			/* Create memory for new ring buffer */
			struct image_data *tmp;
			tmp = mymalloc(new_size * sizeof(struct image_data));

			/* Copy all information from old to new 
			 * Smallest is 0 at initial init */
			if (smallest > 0) 
				memcpy(tmp, cnt->imgs.image_ring, sizeof(struct image_data) * smallest);


			/* In the new buffers, allocate image memory */
			{
				int i;
				for(i = smallest; i < new_size; i++) {
					tmp[i].image = mymalloc(cnt->imgs.size);
					memset(tmp[i].image, 0x80, cnt->imgs.size);  /* initialize to grey */
				}
			}

			/* Free the old ring */
			free(cnt->imgs.image_ring);

			/* Point to the new ring */
			cnt->imgs.image_ring = tmp;

			cnt->imgs.image_ring_size = new_size;
		}
	}
}

static void image_ring_destroy(struct context *cnt)
{
	unsigned short int i;

	/* Exit if don't have any ring */
	if (cnt->imgs.image_ring == NULL)
		return;

	/* Free all image buffers */
	for (i = 0; i < cnt->imgs.image_ring_size; i++) 
		free(cnt->imgs.image_ring[i].image);


	/* Free the ring */
	free(cnt->imgs.image_ring);

	cnt->imgs.image_ring = NULL;
	cnt->imgs.image_ring_size = 0;
}
static void context_init (struct context *cnt)
{
	/*
	 * We first clear the entire structure to zero, then fill in any
	 * values which have non-zero default values.  Note that this
	 * assumes that a NULL address pointer has a value of binary 0
	 * (this is also assumed at other places within the code, i.e.
	 * there are instances of "if (ptr)").  Just for possible future
	 * changes to this assumption, any pointers which are intended
	 * to be initialised to NULL are listed within a comment.
	 */

	memset(cnt, 0, sizeof(struct context));
	cnt->noise = 255;
	cnt->lastrate = 25;

	//memcpy(&cnt->track, &track_template, sizeof(struct trackoptions));
	cnt->pipe = -1;
	cnt->mpipe = -1;

}
static void context_destroy(struct context *cnt)
{
	unsigned short int j;

	/* Free memory allocated for config parameters */
	for (j = 0; config_params[j].param_name != NULL; j++)
	{
		if (config_params[j].copy == copy_string) {
			void **val;
			val = (void *)((char *)cnt+(int)config_params[j].conf_value);
			if (*val) {
				free(*val);
				*val = NULL;
			}
		}
	}

	free(cnt);
}

static void sig_handler(int signo)
{
	short int i;

	switch(signo) {
		case SIGALRM:
			/* Somebody (maybe we ourself) wants us to make a snapshot
			 * This feature triggers snapshots on ALL threads that have
			 * snapshot_interval different from 0.
			 */
			if (cnt_list) {
				i = -1;
				while (cnt_list[++i]) {
					if (cnt_list[i]->conf.snapshot_interval) 
						cnt_list[i]->snapshot = 1;

				}
			}
			break;
		case SIGUSR1:
			/* Ouch! We have been hit from the outside! Someone wants us to
			   make a movie! */
			if (cnt_list) {
				i = -1;
				while (cnt_list[++i])
					cnt_list[i]->makemovie = 1;
			}
			break;
		case SIGHUP:
			restart = 1;
			/* Fall through, as the value of 'restart' is the only difference
			 * between SIGHUP and the ones below.
			 */
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			/* Somebody wants us to quit! We should better finish the actual
			   movie and end up! */
			if (cnt_list) {
				i = -1;
				while (cnt_list[++i]) {
					cnt_list[i]->makemovie = 1;
					cnt_list[i]->finish = 1;
					/* don't restart thread when it ends, 
					 * all threads restarts if global restart is set 
					 */
					cnt_list[i]->restart = 0;
				}
			}
			/* Set flag we want to quit main check threads loop
			 * if restart is set (above) we start up again */
			finish = 1;
			break;
		case SIGSEGV:
			exit(0);
	}
}

static void sigchild_handler(int signo ATTRIBUTE_UNUSED)
{
#ifdef WNOHANG
	while (waitpid(-1, NULL, WNOHANG) > 0) {};
#endif /* WNOHANG */
	return;
}

static void motion_remove_pid(void)
{
	if ((cnt_list[0]->daemon) && (cnt_list[0]->conf.pid_file) && (restart == 0)) {
		if (!unlink(cnt_list[0]->conf.pid_file)) 
			motion_log(LOG_INFO, 0, "Removed process id file (pid file).");
		else 
			motion_log(LOG_INFO, 1, "Error removing pid file");
	}
}

static void motion_detected(struct context *cnt, int dev, struct image_data *img)
{
	struct config *conf = &cnt->conf;
	struct images *imgs = &cnt->imgs;
	struct coord *location = &img->location;

	/* Do things only if we have got minimum_motion_frames */
	if (img->flags & IMAGE_TRIGGER)
	{
		/* Take action if this is a new event and we have a trigger image */
		if (cnt->event_nr != cnt->prev_event) 
		{
			/* Reset prev_event number to current event and save event time
			 * in both time_t and struct tm format.
			 */
			cnt->prev_event = cnt->event_nr;
			cnt->eventtime = img->timestamp;
			localtime_r(&cnt->eventtime, cnt->eventtime_tm);

			/* Since this is a new event we create the event_text_string used for
			 * the %C conversion specifier. We may already need it for
			 * on_motion_detected_commend so it must be done now.
			 */
			mystrftime(cnt, cnt->text_event_string, sizeof(cnt->text_event_string),
					cnt->conf.text_event, cnt->eventtime_tm, NULL, 0);

			/* EVENT_FIRSTMOTION triggers on_event_start_command and event_ffmpeg_newfile */

			event_ffmpeg_newfile(cnt, 0, img->image, NULL, NULL, &img->timestamp_tm);

			if (cnt->conf.setup_mode)
				motion_log(-1, 0, "Motion detected - starting event %d", cnt->event_nr);
		}
	}
	event_ffmpeg_put(cnt, 0, img->image, NULL, NULL, &img->timestamp_tm);
	event_image_detect(cnt, 0, img->image, NULL, NULL, &img->timestamp_tm);

}

#define IMAGE_BUFFER_FLUSH ((unsigned int)-1)
static int motion_init(struct context *cnt)
{
	int i;
	FILE *picture;

	/* Store thread number in TLS. */
	pthread_setspecific(tls_key_threadnr, (void *)((unsigned long)cnt->threadnr));

	cnt->currenttime_tm = mymalloc(sizeof(struct tm));
	cnt->eventtime_tm = mymalloc(sizeof(struct tm));
	/* Init frame time */
	cnt->currenttime = time(NULL);
	localtime_r(&cnt->currenttime, cnt->currenttime_tm);

	cnt->smartmask_speed = 0;

	/* We initialize cnt->event_nr to 1 and cnt->prev_event to 0 (not really needed) so
	 * that certain code below does not run until motion has been detected the first time */
	cnt->event_nr = 1;
	cnt->prev_event = 0;
	cnt->lightswitch_framecounter = 0;
	cnt->detecting_motion = 0;
	cnt->makemovie = 0;

	motion_log(LOG_DEBUG, 0, "Thread %d started", (unsigned long)pthread_getspecific(tls_key_threadnr));

	if (!cnt->conf.filepath)
		cnt->conf.filepath = strdup(".");

	/* set the device settings */
	cnt->video_dev = vid_start(cnt);

	/* We failed to get an initial image from a camera
	 * So we need to guess height and width based on the config
	 * file options.
	 */
	image_ring_resize(cnt, 1); /* Create a initial precapture ring buffer with 1 frame */

	cnt->imgs.ref = mymalloc(cnt->imgs.size);
	cnt->imgs.out = mymalloc(cnt->imgs.size);
	memset(cnt->imgs.out, 0, cnt->imgs.size);
	/* contains the moving objects of ref. frame */
	cnt->imgs.ref_dyn = mymalloc(cnt->imgs.motionsize * sizeof(cnt->imgs.ref_dyn));
	cnt->imgs.image_virgin = mymalloc(cnt->imgs.size);
	cnt->imgs.smartmask = mymalloc(cnt->imgs.motionsize);
	cnt->imgs.smartmask_final = mymalloc(cnt->imgs.motionsize);
	cnt->imgs.smartmask_buffer = mymalloc(cnt->imgs.motionsize * sizeof(cnt->imgs.smartmask_buffer));
	cnt->imgs.labels = mymalloc(cnt->imgs.motionsize * sizeof(cnt->imgs.labels));
	cnt->imgs.labelsize = mymalloc((cnt->imgs.motionsize/2+1) * sizeof(cnt->imgs.labelsize));

	/* allocate buffer here for preview buffer */
	cnt->imgs.preview_image.image = mymalloc(cnt->imgs.size);

	/* Allocate a buffer for temp. usage in some places */
	/* Only despeckle & bayer2rgb24() for now for now... */
	cnt->imgs.common_buffer = mymalloc(3 * cnt->imgs.width * cnt->imgs.height);

	/* Now is a good time to init rotation data. Since vid_start has been
	 * called, we know that we have imgs.width and imgs.height. When capturing
	 * from a V4L device, these are copied from the corresponding conf values
	 * in vid_start. When capturing from a netcam, they get set in netcam_start,
	 * which is called from vid_start.
	 *
	 * rotate_init will set cap_width and cap_height in cnt->rotate_data.
	 */
	rotate_init(cnt); /* rotate_deinit is called in main */

	/* Capture first image, or we will get an alarm on start */
	if (cnt->video_dev > 0) {
		for (i = 0; i < 5; i++) {
			if (vid_next(cnt, cnt->imgs.image_virgin) == 0)
				break;
			SLEEP(2,0);
		}
		if (i >= 5) {
			memset(cnt->imgs.image_virgin, 0x80, cnt->imgs.size);       /* initialize to grey */
			//draw_text(cnt->imgs.image_virgin, 10, 20, cnt->imgs.width,
			//		"Error capturing first image", cnt->conf.text_double);
			motion_log(LOG_ERR, 0, "Error capturing first image");
		}
	}

	/* create a reference frame */
	//alg_update_reference_frame(cnt, RESET_REF_FRAME);

#if !defined(WITHOUT_V4L) && !defined(BSD)
	/* open video loopback devices if enabled */
	if (cnt->conf.vidpipe) {
		if (cnt->conf.setup_mode)
			motion_log(-1, 0, "Opening video loopback device for normal pictures");

		/* vid_startpipe should get the output dimensions */
		cnt->pipe = vid_startpipe(cnt->conf.vidpipe, cnt->imgs.width, cnt->imgs.height, cnt->imgs.type);

		if (cnt->pipe < 0) {
			motion_log(LOG_ERR, 0, "Failed to open video loopback");
			return -1;
		}
	}
	if (cnt->conf.motionvidpipe) {
		if (cnt->conf.setup_mode)
			motion_log(-1, 0, "Opening video loopback device for motion pictures");

		/* vid_startpipe should get the output dimensions */
		cnt->mpipe = vid_startpipe(cnt->conf.motionvidpipe, cnt->imgs.width, cnt->imgs.height, cnt->imgs.type);

		if (cnt->mpipe < 0) {
			motion_log(LOG_ERR, 0, "Failed to open video loopback");
			return -1;
		}
	}
#endif /*WITHOUT_V4L && !BSD */

#ifdef HAVE_MYSQL
	if (cnt->conf.mysql_db) {
		cnt->database = (MYSQL *) mymalloc(sizeof(MYSQL));
		mysql_init(cnt->database);

		if (!mysql_real_connect(cnt->database, cnt->conf.mysql_host, cnt->conf.mysql_user,
					cnt->conf.mysql_password, cnt->conf.mysql_db, 0, NULL, 0)) {
			motion_log(LOG_ERR, 0, "Cannot connect to MySQL database %s on host %s with user %s",
					cnt->conf.mysql_db, cnt->conf.mysql_host, cnt->conf.mysql_user);
			motion_log(LOG_ERR, 0, "MySQL error was %s", mysql_error(cnt->database));
			return -2;
		}
#if (defined(MYSQL_VERSION_ID)) && (MYSQL_VERSION_ID > 50012)
		my_bool my_true = TRUE;
		mysql_options(cnt->database,MYSQL_OPT_RECONNECT,&my_true);
#endif
	}
#endif /* HAVE_MYSQL */

#ifdef HAVE_PGSQL
	if (cnt->conf.pgsql_db) {
		char connstring[255];

		/* create the connection string.
		   Quote the values so we can have null values (blank)*/
		snprintf(connstring, 255,
				"dbname='%s' host='%s' user='%s' password='%s' port='%d'",
				cnt->conf.pgsql_db, /* dbname */
				(cnt->conf.pgsql_host ? cnt->conf.pgsql_host : ""), /* host (may be blank) */
				(cnt->conf.pgsql_user ? cnt->conf.pgsql_user : ""), /* user (may be blank) */
				(cnt->conf.pgsql_password ? cnt->conf.pgsql_password : ""), /* password (may be blank) */
				cnt->conf.pgsql_port
				);

		cnt->database_pg = PQconnectdb(connstring);

		if (PQstatus(cnt->database_pg) == CONNECTION_BAD) {
			motion_log(LOG_ERR, 0, "Connection to PostgreSQL database '%s' failed: %s",
					cnt->conf.pgsql_db, PQerrorMessage(cnt->database_pg));
			return -2;
		}
	}
#endif /* HAVE_PGSQL */


#if defined(HAVE_MYSQL) || defined(HAVE_PGSQL)
	/* Set the sql mask file according to the SQL config options*/

	cnt->sql_mask = cnt->conf.sql_log_image * (FTYPE_IMAGE + FTYPE_IMAGE_MOTION) +
		cnt->conf.sql_log_snapshot * FTYPE_IMAGE_SNAPSHOT +
		cnt->conf.sql_log_mpeg * (FTYPE_MPEG + FTYPE_MPEG_MOTION) +
		cnt->conf.sql_log_timelapse * FTYPE_MPEG_TIMELAPSE;
#endif /* defined(HAVE_MYSQL) || defined(HAVE_PGSQL) */

	/* Load the mask file if any */
	if (cnt->conf.mask_file) {
		if ((picture = fopen(cnt->conf.mask_file, "r"))) {
			/* NOTE: The mask is expected to have the output dimensions. I.e., the mask
			 * applies to the already rotated image, not the capture image. Thus, use
			 * width and height from imgs.
			 */
			cnt->imgs.mask = get_pgm(picture, cnt->imgs.width, cnt->imgs.height);
			fclose(picture);
		} else {
			motion_log(LOG_ERR, 1, "Error opening mask file %s", cnt->conf.mask_file);
			/* Try to write an empty mask file to make it easier
			   for the user to edit it */
			put_fixed_mask(cnt, cnt->conf.mask_file);
		}

		if (!cnt->imgs.mask) {
			motion_log(LOG_ERR, 0, "Failed to read mask image. Mask feature disabled.");
		} else {
			if (cnt->conf.setup_mode)
				motion_log(-1, 0, "Maskfile \"%s\" loaded.",cnt->conf.mask_file);
		}

	} else {
		cnt->imgs.mask = NULL;
	}    

	/* Always initialize smart_mask - someone could turn it on later... */
	memset(cnt->imgs.smartmask, 0, cnt->imgs.motionsize);
	memset(cnt->imgs.smartmask_final, 255, cnt->imgs.motionsize);
	memset(cnt->imgs.smartmask_buffer, 0, cnt->imgs.motionsize*sizeof(cnt->imgs.smartmask_buffer));

	/* Set noise level */
	cnt->noise = cnt->conf.noise;

	/* Set threshold value */
	cnt->threshold = cnt->conf.max_changes;
#if 0
	/* Initialize webcam server if webcam port is specified to not 0 */
	if (cnt->conf.webcam_port) {
		if (webcam_init(cnt) == -1) {
			motion_log(LOG_ERR, 1, "Problem enabling stream server in port %d", cnt->conf.webcam_port);
			cnt->finish = 1;
		} else {    
			motion_log(LOG_DEBUG, 0, "Started stream webcam server in port %d", cnt->conf.webcam_port);
		}    
	}
#endif
	/* Prevent first few frames from triggering motion... */
	cnt->moved = 8;
	/* 2 sec startup delay so FPS is calculated correct */
	cnt->startup_frames = cnt->conf.frame_limit * 2;

	return 0;
}
static void motion_cleanup(struct context *cnt)
{
	/* Stop webcam */
//	event(cnt, EVENT_STOP, NULL, NULL, NULL, NULL);
	event_stop_webcam(cnt, NULL, NULL, NULL, NULL, NULL);
	if (cnt->video_dev >= 0) {
		motion_log(LOG_DEBUG, 0, "Calling vid_close() from motion_cleanup");        
		vid_close(cnt);
	}

	if (cnt->imgs.out) {
		free(cnt->imgs.out);
		cnt->imgs.out = NULL;
	}

	if (cnt->imgs.ref) {
		free(cnt->imgs.ref);
		cnt->imgs.ref = NULL;
	}

	if (cnt->imgs.ref_dyn) {
		free(cnt->imgs.ref_dyn);
		cnt->imgs.ref_dyn = NULL;
	}

	if (cnt->imgs.image_virgin) {
		free(cnt->imgs.image_virgin);
		cnt->imgs.image_virgin = NULL;
	}

	if (cnt->imgs.labels) {
		free(cnt->imgs.labels);
		cnt->imgs.labels = NULL;
	}

	if (cnt->imgs.labelsize) {
		free(cnt->imgs.labelsize);
		cnt->imgs.labelsize = NULL;
	}

	if (cnt->imgs.smartmask) {
		free(cnt->imgs.smartmask);
		cnt->imgs.smartmask = NULL;
	}

	if (cnt->imgs.smartmask_final) {
		free(cnt->imgs.smartmask_final);
		cnt->imgs.smartmask_final = NULL;
	}

	if (cnt->imgs.smartmask_buffer) {
		free(cnt->imgs.smartmask_buffer);
		cnt->imgs.smartmask_buffer = NULL;
	}

	if (cnt->imgs.common_buffer) {
		free(cnt->imgs.common_buffer);
		cnt->imgs.common_buffer = NULL;
	}

	if (cnt->imgs.preview_image.image) {
		free(cnt->imgs.preview_image.image);
		cnt->imgs.preview_image.image = NULL;
	}

	image_ring_destroy(cnt); /* Cleanup the precapture ring buffer */

	rotate_deinit(cnt); /* cleanup image rotation data */

	if (cnt->pipe != -1) {
		close(cnt->pipe);
		cnt->pipe = -1;
	}

	if (cnt->mpipe != -1) {
		close(cnt->mpipe);
		cnt->mpipe = -1;
	}

	/* Cleanup the current time structure */
	if (cnt->currenttime_tm) {
		free(cnt->currenttime_tm);
		cnt->currenttime_tm = NULL;
	}

	/* Cleanup the event time structure */
	if (cnt->eventtime_tm) {
		free(cnt->eventtime_tm);
		cnt->eventtime_tm = NULL;
	}
}
static void *motion_loop(void *arg)
{
	struct context *cnt = arg;
	int i, j, z = 0;
	time_t lastframetime = 0;
	int frame_buffer_size;
	unsigned short int ref_frame_limit = 0;
	int area_once = 0;
	int area_minx[9], area_miny[9], area_maxx[9], area_maxy[9];
	int smartmask_ratio = 0;
	int smartmask_count = 20;
	int smartmask_lastrate = 0;
	int olddiffs = 0;
	int previous_diffs = 0, previous_location_x = 0, previous_location_y = 0;
	unsigned short int text_size_factor;
	unsigned short int passflag = 0;
	long int *rolling_average_data = NULL;
	long int rolling_average_limit, required_frame_time, frame_delay, delay_time_nsec;
	int rolling_frame = 0;
	struct timeval tv1, tv2;
	unsigned long int rolling_average, elapsedtime;
	unsigned long long int timenow = 0, timebefore = 0;
	/* Return code used when calling vid_next */
	int vid_return_code = 0;       
	/* time in seconds to skip between capturing images */
	int minimum_frame_time_downcounter = cnt->conf.minimum_frame_time;
	/* Flag used to signal that we capture new image when we run the loop */
	unsigned short int get_image = 1;

	/* Next two variables are used for snapshot and timelapse feature
	 * time_last_frame is set to 1 so that first coming timelapse or second=0
	 * is acted upon.
	 */
	unsigned long int time_last_frame=1, time_current_frame;

	cnt->running = 1;

	if (motion_init(cnt) < 0) 
		goto err;
	/* MAIN MOTION LOOP BEGINS HERE */
	/* Should go on forever... unless you bought vaporware :) */


	while (!cnt->finish || cnt->makemovie) 
	{
		/***** MOTION LOOP - PREPARE FOR NEW FRAME SECTION *****/
		/* Get current time and preserver last time for frame interval calc. */
		timebefore = timenow;
		gettimeofday(&tv1, NULL);
		timenow = tv1.tv_usec + 1000000L * tv1.tv_sec;
		/* Get time for current frame */
		cnt->currenttime = time(NULL);

		/* localtime returns static data and is not threadsafe
		 * so we use localtime_r which is reentrant and threadsafe
		 */
		localtime_r(&cnt->currenttime, cnt->currenttime_tm);

		/* If we have started on a new second we reset the shots variable
		 * lastrate is updated to be the number of the last frame. last rate
		 * is used as the ffmpeg framerate when motion is detected.
		 */
		if (lastframetime != cnt->currenttime) {
			cnt->lastrate = cnt->shots + 1;
			cnt->shots = -1;
			lastframetime = cnt->currenttime;
			if (cnt->conf.minimum_frame_time) {
				minimum_frame_time_downcounter--;
				if (minimum_frame_time_downcounter == 0)
					get_image = 1;
			} else {
				get_image = 1;
			}    
		}

		/* Increase the shots variable for each frame captured within this second */
		cnt->shots++;

		if (cnt->startup_frames > 0)
			cnt->startup_frames--;

		if (get_image)
		{
			if (cnt->conf.minimum_frame_time) {
				minimum_frame_time_downcounter = cnt->conf.minimum_frame_time;
				get_image = 0;
			}

			/* ring_buffer_in is pointing to current pos, update before put in a new image */
			if (++cnt->imgs.image_ring_in >= cnt->imgs.image_ring_size)
				cnt->imgs.image_ring_in = 0;

			/* Check if we have filled the ring buffer, throw away last image */
			if (cnt->imgs.image_ring_in == cnt->imgs.image_ring_out) {
				if (++cnt->imgs.image_ring_out >= cnt->imgs.image_ring_size)
					cnt->imgs.image_ring_out = 0;
			}

			/* cnt->current_image points to position in ring where to store image, diffs etc. */
			cnt->current_image = &cnt->imgs.image_ring[cnt->imgs.image_ring_in];

			/* Init/clear current_image */
			{
				/* Store time with pre_captured image */
				cnt->current_image->timestamp = cnt->currenttime;
				localtime_r(&cnt->current_image->timestamp, &cnt->current_image->timestamp_tm);

				/* Store shot number with pre_captured image */
				cnt->current_image->shot = cnt->shots;

				/* set diffs to 0 now, will be written after we calculated diffs in new image */
				cnt->current_image->diffs = 0;

				/* Set flags to 0 */
				cnt->current_image->flags = 0;
				cnt->current_image->cent_dist = 0;

				/* Clear location data */
				memset(&cnt->current_image->location, 0, sizeof(cnt->current_image->location));
				cnt->current_image->total_labels = 0;
			}
			/***** MOTION LOOP - IMAGE CAPTURE SECTION *****/
			/* Fetch next frame from camera
			 * If vid_next returns 0 all is well and we got a new picture
			 * Any non zero value is an error.
			 * 0 = OK, valid picture
			 * <0 = fatal error - leave the thread by breaking out of the main loop
			 * >0 = non fatal error - copy last image or show grey image with message
			 */
			if (cnt->video_dev >= 0)
				vid_return_code = vid_next(cnt, cnt->current_image->image);
			else
				vid_return_code = 1; /* Non fatal error */

			// VALID PICTURE
			if (vid_return_code == 0) {
				cnt->lost_connection = 0;
				cnt->connectionlosttime = 0;

				/* If all is well reset missing_frame_counter */
				if (cnt->missing_frame_counter >= MISSING_FRAMES_TIMEOUT * cnt->conf.frame_limit) 
					/* If we previously logged starting a grey image, now log video re-start */
					motion_log(LOG_ERR, 0, "Video signal re-acquired");
				// event for re-acquired video signal can be called here

				cnt->missing_frame_counter = 0;

				/* save the newly captured still virgin image to a buffer
				 * which we will not alter with text and location graphics
				 */
				memcpy(cnt->imgs.image_virgin, cnt->current_image->image, cnt->imgs.size);
			}
			

			/***** MOTION LOOP - ACTIONS AND EVENT CONTROL SECTION *****/
			/* If motion has been detected we take action and start saving
			 * pictures and movies etc by calling motion_detected().
			 * Is output_all enabled we always call motion_detected()
			 * If post_capture is enabled we also take care of this in the this
			 * code section.
			 */
 			if (cnt->conf.output_all && (cnt->startup_frames == 0)) 
			{
				cnt->detecting_motion = 1;
				/* Setup the postcap counter */
				cnt->postcap = cnt->conf.post_capture;
				cnt->current_image->flags |= (IMAGE_TRIGGER | IMAGE_SAVE);
				motion_detected(cnt, cnt->video_dev, cnt->current_image);
			} 
		} /* get_image end */

		time_last_frame = time_current_frame;

		/***** MOTION LOOP - ONCE PER SECOND PARAMETER UPDATE SECTION *****/
		/* Check for some config parameter changes but only every second */
		if (cnt->shots == 0){
			cnt->new_img = NEWIMG_ON;
			cnt->locate = LOCATE_OFF;
			/* Sanity check for smart_mask_speed, silly value disables smart mask */
			if (cnt->conf.smart_mask_speed < 0 || cnt->conf.smart_mask_speed > 10)
				cnt->conf.smart_mask_speed = 0;
		}
		/***** MOTION LOOP - FRAMERATE TIMING AND SLEEPING SECTION *****/
		//sleep(1);
	}
err:
	if (rolling_average_data)
		free(rolling_average_data);

	cnt->lost_connection = 1;
	motion_log(-1, 0, "Thread exiting");

	motion_cleanup(cnt);

	pthread_mutex_lock(&global_lock);
	threads_running--;
	pthread_mutex_unlock(&global_lock);

	if (!cnt->restart)
		cnt->watchdog=WATCHDOG_OFF;

	cnt->running = 0;
	cnt->finish = 0;

	pthread_exit(NULL);
}

/**
 * cntlist_create
 *
 *   Sets up the 'cnt_list' variable by allocating room for (and actually
 *   allocating) one context struct. Also loads the configuration from
 *   the config file(s).
 *
 * Parameters:
 *   argc - size of argv
 *   argv - command-line options, passed initially from 'main'
 *
 * Returns: nothing
 */
static void cntlist_create(int argc, char *argv[])
{
	/* cnt_list is an array of pointers to the context structures cnt for each thread.
	 * First we reserve room for a pointer to thread 0's context structure
	 * and a NULL pointer which indicates that end of the array of pointers to
	 * thread context structures.
	 */
	cnt_list = mymalloc(sizeof(struct context *) * 2);

	/* Now we reserve room for thread 0's context structure and let cnt_list[0] point to it */
	cnt_list[0] = mymalloc(sizeof(struct context));

	/* Populate context structure with start/default values */
	context_init(cnt_list[0]);

	/* cnt_list[1] pointing to zero indicates no more thread context structures - they get added later */
	cnt_list[1] = NULL;

	/* Command line arguments are being pointed to from cnt_list[0] and we call conf_load which loads
	 * the config options from motion.conf, thread config files and the command line.
	 */
	cnt_list[0]->conf.argv = argv;
	cnt_list[0]->conf.argc = argc;
	cnt_list = conf_load(cnt_list);
}


/**
 * motion_shutdown
 *
 *   Responsible for performing cleanup when Motion is shut down or restarted,
 *   including freeing memory for all the context structs as well as for the
 *   context struct list itself.
 *
 * Parameters: none
 *
 * Returns:    nothing
 */
static void motion_shutdown(void)
{
	int i = -1;

	motion_remove_pid();

	while (cnt_list[++i])
		context_destroy(cnt_list[i]);

	free(cnt_list);
	cnt_list = NULL;
#ifndef WITHOUT_V4L
	vid_cleanup();
#endif
}

/**
 * motion_startup
 *
 *   Responsible for initializing stuff when Motion starts up or is restarted,
 *   including daemon initialization and creating the context struct list.
 *
 * Parameters:
 *
 *   daemonize - non-zero to do daemon init (if the config parameters says so),
 *               or 0 to skip it
 *   argc      - size of argv
 *   argv      - command-line options, passed initially from 'main'
 *
 * Returns: nothing
 */
static void motion_startup(int daemonize, int argc, char *argv[])
{
	/* Initialize our global mutex */
	pthread_mutex_init(&global_lock, NULL);

	/* Create the list of context structures and load the
	 * configuration.
	 */
	cntlist_create(argc, argv);

	motion_log(LOG_INFO, 0, "Motion "VERSION" Started");

	//initialize_chars();

#ifndef WITHOUT_V4L
	vid_init();
#endif
}

static void start_motion_thread(struct context *cnt, pthread_attr_t *thread_attr)
{
	int i;

	/* Check the webcam port number for conflicts.
	 * First we check for conflict with the control port.
	 * Second we check for that two threads does not use the same port number
	 * for the webcam. If a duplicate port is found the webcam feature gets disabled (port =0)
	 * for this thread and a warning is written to console and syslog.
	 */

	if (cnt->conf.webcam_port != 0) {
		/* Compare against the control port. */
		if (cnt_list[0]->conf.control_port == cnt->conf.webcam_port) {
			motion_log(LOG_ERR, 0,
					"Webcam port number %d for thread %d conflicts with the control port",
					cnt->conf.webcam_port, cnt->threadnr);
			motion_log(LOG_ERR, 0, "Webcam feature for thread %d is disabled.", cnt->threadnr);
			cnt->conf.webcam_port = 0;
		}

		/* Compare against webcam ports of other threads. */
		for (i = 1; cnt_list[i]; i++) {
			if (cnt_list[i] == cnt)
				continue;

			if (cnt_list[i]->conf.webcam_port == cnt->conf.webcam_port) {
				motion_log(LOG_ERR, 0,
						"Webcam port number %d for thread %d conflicts with thread %d",
						cnt->conf.webcam_port, cnt->threadnr, cnt_list[i]->threadnr);
				motion_log(LOG_ERR, 0,
						"Webcam feature for thread %d is disabled.", cnt->threadnr);
				cnt->conf.webcam_port = 0;
			}
		}
	}

	/* Update how many threads we have running. This is done within a
	 * mutex lock to prevent multiple simultaneous updates to
	 * 'threads_running'.
	 */
	pthread_mutex_lock(&global_lock);
	threads_running++;
	pthread_mutex_unlock(&global_lock);

	/* Set a flag that we want this thread running */
	cnt->restart = 1;

	/* Give the thread WATCHDOG_TMO seconds to start */
	cnt->watchdog = WATCHDOG_TMO;

	/* Create the actual thread. Use 'motion_loop' as the thread
	 * function.
	 */
	pthread_create(&cnt->thread_id, thread_attr, &motion_loop, cnt);
}

/**
 * main
 *
 *   Main entry point of Motion. Launches all the motion threads and contains
 *   the logic for starting up, restarting and cleaning up everything.
 *
 * Parameters:
 *
 *   argc - size of argv
 *   argv - command-line options
 *
 * Returns: Motion exit status = 0 always
 */
my_main(int a, int argc, char *argv[])
{
	pthread_attr_t thread_attr;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);

	motion_startup(1, argc, argv);


	ffmpeg_init();

	start_motion_thread(cnt_list[0], &thread_attr);

	while(1)
		sleep(10);
}

int main (int argc, char **argv)
{
	my_main(1, argc, argv); return 0;

}

void * mymalloc(size_t nbytes)
{
	void *dummy = malloc(nbytes);
	if (!dummy) {
		motion_log(LOG_EMERG, 1, "Could not allocate %llu bytes of memory!", (unsigned long long)nbytes);
		motion_remove_pid();
		exit(1);
	}

	return dummy;
}

void *myrealloc(void *ptr, size_t size, const char *desc)
{
	void *dummy = NULL;

	if (size == 0) {
		free(ptr);
		motion_log(LOG_WARNING, 0,
				"Warning! Function %s tries to resize memoryblock at %p to 0 bytes!",
				desc, ptr);
	} else {
		dummy = realloc(ptr, size);
		if (!dummy) {
			motion_log(LOG_EMERG, 0,
					"Could not resize memory-block at offset %p to %llu bytes (function %s)!",
					ptr, (unsigned long long)size, desc);
			motion_remove_pid();
			exit(1);
		}
	}

	return dummy;
}

/**
 * create_path
 *
 *   This function creates a whole path, like mkdir -p. Example paths:
 *      this/is/an/example/
 *      /this/is/an/example/
 *   Warning: a path *must* end with a slash!
 *
 * Parameters:
 *
 *   cnt  - current thread's context structure (for logging)
 *   path - the path to create
 *
 * Returns: 0 on success, -1 on failure
 */
int create_path(const char *path)
{
	char *start;
	mode_t mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

	if (path[0] == '/')
		start = strchr(path + 1, '/');
	else
		start = strchr(path, '/');

	while (start) {
		char *buffer = strdup(path);
		buffer[start-path] = 0x00;

		if (mkdir(buffer, mode) == -1 && errno != EEXIST) {
			motion_log(LOG_ERR, 1, "Problem creating directory %s", buffer);
			free(buffer);
			return -1;
		}

		free(buffer);

		start = strchr(start + 1, '/');
	}

	return 0;
}

/**
 * myfopen
 *
 *   This function opens a file, if that failed because of an ENOENT error
 *   (which is: path does not exist), the path is created and then things are
 *   tried again. This is faster then trying to create that path over and over
 *   again. If someone removes the path after it was created, myfopen will
 *   recreate the path automatically.
 *
 * Parameters:
 *
 *   path - path to the file to open
 *   mode - open mode
 *
 * Returns: the file stream object
 */
FILE * myfopen(const char *path, const char *mode)
{
	/* first, just try to open the file */
	FILE *dummy = fopen(path, mode);

	/* could not open file... */
	if (!dummy) {
		/* path did not exist? */
		if (errno == ENOENT) {

			/* create path for file... */
			if (create_path(path) == -1)
				return NULL;

			/* and retry opening the file */
			dummy = fopen(path, mode);
			if (dummy)
				return dummy;
		}

		/* two possibilities
		 * 1: there was an other error while trying to open the file for the first time
		 * 2: could still not open the file after the path was created
		 */
		motion_log(LOG_ERR, 1, "Error opening file %s with mode %s", path, mode);

		return NULL;
	}

	return dummy;
}

/**
 * mystrftime
 *
 *   Motion-specific variant of strftime(3) that supports additional format
 *   specifiers in the format string.
 *
 * Parameters:
 *
 *   cnt        - current thread's context structure
 *   s          - destination string
 *   max        - max number of bytes to write
 *   userformat - format string
 *   tm         - time information
 *   filename   - string containing full path of filename
 *                set this to NULL if not relevant
 *   sqltype    - Filetype as used in SQL feature, set to 0 if not relevant
 *
 * Returns: number of bytes written to the string s
 */
size_t mystrftime(struct context *cnt, char *s, size_t max, const char *userformat,
		const struct tm *tm, const char *filename, int sqltype)
{
	char formatstring[PATH_MAX] = "";
	char tempstring[PATH_MAX] = "";
	char *format, *tempstr;
	const char *pos_userformat;

	format = formatstring;

	/* if mystrftime is called with userformat = NULL we return a zero length string */
	if (userformat == NULL) {
		*s = '\0';
		return 0;
	}

	for (pos_userformat = userformat; *pos_userformat; ++pos_userformat) {

		if (*pos_userformat == '%') {
			/* Reset 'tempstr' to point to the beginning of 'tempstring',
			 * otherwise we will eat up tempstring if there are many
			 * format specifiers.
			 */
			tempstr = tempstring;
			tempstr[0] = '\0';
			switch (*++pos_userformat) {
				case '\0': // end of string
					--pos_userformat;
					break;

				case 'v': // event
					sprintf(tempstr, "%02d", cnt->event_nr);
					break;

				case 'q': // shots
					sprintf(tempstr, "%02d", cnt->current_image->shot);
					break;

				case 'D': // diffs
					sprintf(tempstr, "%d", cnt->current_image->diffs);
					break;

				case 'N': // noise
					sprintf(tempstr, "%d", cnt->noise);
					break;

				case 'i': // motion width
					sprintf(tempstr, "%d", cnt->current_image->location.width);
					break;

				case 'J': // motion height
					sprintf(tempstr, "%d", cnt->current_image->location.height);
					break;

				case 'K': // motion center x
					sprintf(tempstr, "%d", cnt->current_image->location.x);
					break;

				case 'L': // motion center y
					sprintf(tempstr, "%d", cnt->current_image->location.y);
					break;

				case 'o': // threshold
					sprintf(tempstr, "%d", cnt->threshold);
					break;

				case 'Q': // number of labels
					sprintf(tempstr, "%d", cnt->current_image->total_labels);
					break;
				case 't': // thread number
					sprintf(tempstr, "%d",(int)(unsigned long)
							pthread_getspecific(tls_key_threadnr));
					break;
				case 'C': // text_event
					if (cnt->text_event_string && cnt->text_event_string[0])
						snprintf(tempstr, PATH_MAX, "%s", cnt->text_event_string);
					else
						++pos_userformat;
					break;
				case 'f': // filename
					if (filename)
						snprintf(tempstr, PATH_MAX, "%s", filename);
					else
						++pos_userformat;
					break;
				case 'n': // sqltype
					if (sqltype)
						sprintf(tempstr, "%d", sqltype);
					else
						++pos_userformat;
					break;
				default: // Any other code is copied with the %-sign
					*format++ = '%';
					*format++ = *pos_userformat;
					continue;
			}

			/* If a format specifier was found and used, copy the result from
			 * 'tempstr' to 'format'.
			 */
			if (tempstr[0]) {
				while ((*format = *tempstr++) != '\0')
					++format;
				continue;
			}
		}

		/* For any other character than % we just simply copy the character */
		*format++ = *pos_userformat;
	}

	*format = '\0';
	format = formatstring;

	return strftime(s, max, format, tm);
}

/**
 * motion_log
 *
 *    This routine is used for printing all informational, debug or error
 *    messages produced by any of the other motion functions.  It always
 *    produces a message of the form "[n] {message}", and (if the param
 *    'errno_flag' is set) follows the message with the associated error
 *    message from the library.
 *
 * Parameters:
 *
 *     level           logging level for the 'syslog' function
 *                     (-1 implies no syslog message should be produced)
 *     errno_flag      if set, the log message should be followed by the
 *                     error message.
 *     fmt             the format string for producing the message
 *     ap              variable-length argument list
 *
 * Returns:
 *                     Nothing
 */
void motion_log(int level, int errno_flag, const char *fmt, ...)
{
	int errno_save, n;
	char buf[1024];
#if (!defined(BSD)) && (!(_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE)
	char msg_buf[100];
#endif
	va_list ap;
	int threadnr;

	/* If pthread_getspecific fails (e.g., because the thread's TLS doesn't
	 * contain anything for thread number, it returns NULL which casts to zero,
	 * which is nice because that's what we want in that case.
	 */
	threadnr = (unsigned long)pthread_getspecific(tls_key_threadnr);

	/*
	 * First we save the current 'error' value.  This is required because
	 * the subsequent calls to vsnprintf could conceivably change it!
	 */
	errno_save = errno;

	/* Prefix the message with the thread number */
	n = snprintf(buf, sizeof(buf), "[%d] ", threadnr);

	/* Next add the user's message */
	va_start(ap, fmt);
	n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);

	/* If errno_flag is set, add on the library error message */
	if (errno_flag) {
		strncat(buf, ": ", 1024 - strlen(buf));
		n += 2;

		/*
		 * this is bad - apparently gcc/libc wants to use the non-standard GNU
		 * version of strerror_r, which doesn't actually put the message into
		 * my buffer :-(.  I have put in a 'hack' to get around this.
		 */
#if (defined(BSD))
		strerror_r(errno_save, buf + n, sizeof(buf) - n);    /* 2 for the ': ' */
#elif (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
		strerror_r(errno_save, buf + n, sizeof(buf) - n);
#else
		strncat(buf, strerror_r(errno_save, msg_buf, sizeof(msg_buf)), 1024 - strlen(buf));
#endif
	}
	/* If 'level' is not negative, send the message to the syslog */
	if (level >= 0)
		syslog(level, "%s", buf);

	/* For printing to stderr we need to add a newline */
	strcat(buf, "\n");
	fputs(buf, stderr);
	fflush(stderr);

	/* Clean up the argument list routine */
	va_end(ap);
}



