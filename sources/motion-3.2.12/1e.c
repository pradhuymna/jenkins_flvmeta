#include "ffmpeg.h"    /* must be first to avoid 'shadow' warning */
#include "picture.h"    /* already includes motion.h */
#include "event.h"
#if !defined(BSD) 
#include "video.h"
#endif

void event_newfile(struct context *cnt ATTRIBUTE_UNUSED,
            int type ATTRIBUTE_UNUSED, unsigned char *dummy ATTRIBUTE_UNUSED,
            char *filename, void *ftype, struct tm *tm ATTRIBUTE_UNUSED)
{
    motion_log(-1, 0, "File of type %ld saved to: %s", (unsigned long)ftype, filename);
}
void event_stop_webcam(struct context *cnt, int type ATTRIBUTE_UNUSED,
            unsigned char *dummy1 ATTRIBUTE_UNUSED,
            char *dummy2 ATTRIBUTE_UNUSED, void *dummy3 ATTRIBUTE_UNUSED,
            struct tm *tm ATTRIBUTE_UNUSED)
{
    //if ((cnt->conf.webcam_port) && (cnt->webcam.socket != -1))
        //webcam_stop(cnt);
    
}

const char *imageext(struct context *cnt)
{
    if (cnt->conf.ppm)
        return "ppm";
    return "jpg";
}

void event_image_detect(struct context *cnt, int type ATTRIBUTE_UNUSED,
        unsigned char *newimg, char *dummy1 ATTRIBUTE_UNUSED,
        void *dummy2 ATTRIBUTE_UNUSED, struct tm *currenttime_tm)
{
    char fullfilename[PATH_MAX];
    char filename[PATH_MAX];

    if (cnt->new_img & NEWIMG_ON) {
        const char *jpegpath;

        /* conf.jpegpath would normally be defined but if someone deleted it by control interface
           it is better to revert to the default than fail */
        if (cnt->conf.jpegpath)
            jpegpath = cnt->conf.jpegpath;
        else
            jpegpath = DEF_JPEGPATH;
            
        mystrftime(cnt, filename, sizeof(filename), jpegpath, currenttime_tm, NULL, 0);
        snprintf(fullfilename, PATH_MAX, "%s/%s.%s", cnt->conf.filepath, filename, imageext(cnt));
        put_picture(cnt, fullfilename, newimg, FTYPE_IMAGE);
    }
}

static void grey2yuv420p(unsigned char *u, unsigned char *v, int width, int height)
{
    memset(u, 128, width * height / 4);
    memset(v, 128, width * height / 4);
}
void event_ffmpeg_newfile(struct context *cnt, int type ATTRIBUTE_UNUSED,
            unsigned char *img, char *dummy1 ATTRIBUTE_UNUSED,
            void *dummy2 ATTRIBUTE_UNUSED, struct tm *currenttime_tm)
{
    int width = cnt->imgs.width;
    int height = cnt->imgs.height;
    unsigned char *convbuf, *y, *u, *v;
    int fps = 0;
    char stamp[PATH_MAX];
    const char *mpegpath;

    if (!cnt->conf.ffmpeg_cap_new && !cnt->conf.ffmpeg_cap_motion)
        return;
        
    /* conf.mpegpath would normally be defined but if someone deleted it by control interface
       it is better to revert to the default than fail */
    if (cnt->conf.mpegpath)
        mpegpath = cnt->conf.mpegpath;
    else
        mpegpath = DEF_MPEGPATH;

    mystrftime(cnt, stamp, sizeof(stamp), mpegpath, currenttime_tm, NULL, 0);

    /* motion mpegs get the same name as normal mpegs plus an appended 'm' */
    /* PATH_MAX - 4 to allow for .mpg to be appended without overflow */
    snprintf(cnt->motionfilename, PATH_MAX - 4, "%s/%sm", cnt->conf.filepath, stamp);
    snprintf(cnt->newfilename, PATH_MAX - 4, "%s/%s", cnt->conf.filepath, stamp);

    if (cnt->conf.ffmpeg_cap_new) {
        if (cnt->imgs.type == VIDEO_PALETTE_GREY) {
            convbuf=mymalloc((width * height) / 2);
            y = img;
            u = convbuf;
            v = convbuf + (width * height) / 4;
            grey2yuv420p(u, v, width, height);
        } else {
            convbuf = NULL;
            y = img;
            u = img + width * height;
            v = u + (width * height) / 4;
        }

        fps = cnt->lastrate;

        if (debug_level >= CAMERA_DEBUG) 
            motion_log(LOG_DEBUG, 0, "%s FPS %d",__FUNCTION__, fps);

        if (fps > 30)
            fps = 30;
        else if (fps < 2)
            fps = 2;

        if ((cnt->ffmpeg_new =
             ffmpeg_open((char *)cnt->conf.ffmpeg_video_codec, cnt->newfilename, y, u, v,
                         cnt->imgs.width, cnt->imgs.height, fps, cnt->conf.ffmpeg_bps,
                         cnt->conf.ffmpeg_vbr)) == NULL) {
            motion_log(LOG_ERR, 1, "ffopen_open error creating (new) file [%s]",cnt->newfilename);
            cnt->finish = 1;
            return;
        }
        ((struct ffmpeg *)cnt->ffmpeg_new)->udata=convbuf;
		event_newfile(cnt, NULL, NULL, cnt->newfilename, (void *)FTYPE_MPEG, NULL);
    }
}

void event_ffmpeg_put(struct context *cnt, int type ATTRIBUTE_UNUSED,
            unsigned char *img, char *dummy1 ATTRIBUTE_UNUSED,
            void *dummy2 ATTRIBUTE_UNUSED, struct tm *tm ATTRIBUTE_UNUSED)
{
    if (cnt->ffmpeg_new) {
        int width=cnt->imgs.width;
        int height=cnt->imgs.height;
        unsigned char *y = img;
        unsigned char *u, *v;
        
        if (cnt->imgs.type == VIDEO_PALETTE_GREY)
            u = cnt->ffmpeg_timelapse->udata;
        else
            u = y + (width * height);
        
        v = u + (width * height) / 4;
        ffmpeg_put_other_image(cnt->ffmpeg_new, y, u, v);
    }
    
    if (cnt->ffmpeg_motion) 
        ffmpeg_put_image(cnt->ffmpeg_motion);
    
}
