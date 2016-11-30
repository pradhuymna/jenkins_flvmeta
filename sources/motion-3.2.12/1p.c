#include "picture.h"
#include "event.h"

#undef HAVE_STDLIB_H
#include <jpeglib.h>
#include <jerror.h>

typedef struct {
    struct jpeg_destination_mgr pub;
    JOCTET *buf;
    size_t bufsize;
    size_t jpegsize;
} mem_destination_mgr;

typedef mem_destination_mgr *mem_dest_ptr;


METHODDEF(void) init_destination(j_compress_ptr cinfo)
{
    mem_dest_ptr dest = (mem_dest_ptr) cinfo->dest;
    dest->pub.next_output_byte = dest->buf;
    dest->pub.free_in_buffer = dest->bufsize;
    dest->jpegsize = 0;
}

METHODDEF(boolean) empty_output_buffer(j_compress_ptr cinfo)
{
    mem_dest_ptr dest = (mem_dest_ptr) cinfo->dest;
    dest->pub.next_output_byte = dest->buf;
    dest->pub.free_in_buffer = dest->bufsize;

    return FALSE;
    ERREXIT(cinfo, JERR_BUFFER_SIZE);
}

METHODDEF(void) term_destination(j_compress_ptr cinfo)
{
    mem_dest_ptr dest = (mem_dest_ptr) cinfo->dest;
    dest->jpegsize = dest->bufsize - dest->pub.free_in_buffer;
}

static GLOBAL(void) _jpeg_mem_dest(j_compress_ptr cinfo, JOCTET* buf, size_t bufsize)
{
    mem_dest_ptr dest;

    if (cinfo->dest == NULL) {
        cinfo->dest = (struct jpeg_destination_mgr *)
                      (*cinfo->mem->alloc_small)((j_common_ptr)cinfo, JPOOL_PERMANENT,
                      sizeof(mem_destination_mgr));
    }

    dest = (mem_dest_ptr) cinfo->dest;

    dest->pub.init_destination    = init_destination;
    dest->pub.empty_output_buffer = empty_output_buffer;
    dest->pub.term_destination    = term_destination;

    dest->buf      = buf;
    dest->bufsize  = bufsize;
    dest->jpegsize = 0;
}

static GLOBAL(int) _jpeg_mem_size(j_compress_ptr cinfo)
{
    mem_dest_ptr dest = (mem_dest_ptr) cinfo->dest;
    return dest->jpegsize;
}


/* put_jpeg_yuv420p_memory converts an input image in the YUV420P format into a jpeg image and puts
 * it in a memory buffer.
 * Inputs:
 * - image_size is the size of the input image buffer.
 * - input_image is the image in YUV420P format.
 * - width and height are the dimensions of the image
 * - quality is the jpeg encoding quality 0-100%
 * Output:
 * - dest_image is a pointer to the jpeg image buffer
 * Returns buffer size of jpeg image     
 */
static int put_jpeg_yuv420p_memory(unsigned char *dest_image, int image_size,
                                   unsigned char *input_image, int width, int height, int quality)
{
    int i, j, jpeg_image_size;

    JSAMPROW y[16],cb[16],cr[16]; // y[2][5] = color sample of row 2 and pixel column 5; (one plane)
    JSAMPARRAY data[3]; // t[0][2][5] = color sample 0 of row 2 and column 5

    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;

    data[0] = y;
    data[1] = cb;
    data[2] = cr;

    cinfo.err = jpeg_std_error(&jerr);  // errors get written to stderr 
    
    jpeg_create_compress(&cinfo);
    cinfo.image_width = width;
    cinfo.image_height = height;
    cinfo.input_components = 3;
    jpeg_set_defaults (&cinfo);

    jpeg_set_colorspace(&cinfo, JCS_YCbCr);

    cinfo.raw_data_in = TRUE; // supply downsampled data
#if JPEG_LIB_VERSION >= 70
#warning using JPEG_LIB_VERSION >= 70
    cinfo.do_fancy_downsampling = FALSE;  // fix segfaulst with v7
#endif    
    cinfo.comp_info[0].h_samp_factor = 2;
    cinfo.comp_info[0].v_samp_factor = 2;
    cinfo.comp_info[1].h_samp_factor = 1;
    cinfo.comp_info[1].v_samp_factor = 1;
    cinfo.comp_info[2].h_samp_factor = 1;
    cinfo.comp_info[2].v_samp_factor = 1;

    jpeg_set_quality(&cinfo, quality, TRUE);
    cinfo.dct_method = JDCT_FASTEST;

    _jpeg_mem_dest(&cinfo, dest_image, image_size);    // data written to mem
    
    jpeg_start_compress (&cinfo, TRUE);

    for (j = 0; j < height; j += 16) {
        for (i = 0; i < 16; i++) {
            y[i] = input_image + width * (i + j);
            if (i%2 == 0) {
                cb[i/2] = input_image + width * height + width / 2 * ((i + j) / 2);
                cr[i/2] = input_image + width * height + width * height / 4 + width / 2 * ((i + j) / 2);
            }
        }
        jpeg_write_raw_data(&cinfo, data, 16);
    }

    jpeg_finish_compress(&cinfo);
    jpeg_image_size = _jpeg_mem_size(&cinfo);
    jpeg_destroy_compress(&cinfo);
    
    return jpeg_image_size;
}
/* put_jpeg_yuv420p_file converts an YUV420P coded image to a jpeg image and writes
 * it to an already open file.
 * Inputs:
 * - image is the image in YUV420P format.
 * - width and height are the dimensions of the image
 * - quality is the jpeg encoding quality 0-100%
 * Output:
 * - The jpeg is written directly to the file given by the file pointer fp
 * Returns nothing
 */
static void put_jpeg_yuv420p_file(FILE *fp, unsigned char *image, int width, 
            int height, int quality)
{
    int i,j;

    JSAMPROW y[16],cb[16],cr[16]; // y[2][5] = color sample of row 2 and pixel column 5; (one plane)
    JSAMPARRAY data[3]; // t[0][2][5] = color sample 0 of row 2 and column 5

    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;

    data[0] = y;
    data[1] = cb;
    data[2] = cr;

    cinfo.err = jpeg_std_error(&jerr);  // errors get written to stderr 
    
    jpeg_create_compress(&cinfo);
    cinfo.image_width = width;
    cinfo.image_height = height;
    cinfo.input_components = 3;
    jpeg_set_defaults(&cinfo);

    jpeg_set_colorspace(&cinfo, JCS_YCbCr);

    cinfo.raw_data_in = TRUE; // supply downsampled data
#if JPEG_LIB_VERSION >= 70
#warning using JPEG_LIB_VERSION >= 70
    cinfo.do_fancy_downsampling = FALSE;  // fix segfaulst with v7
#endif    
    cinfo.comp_info[0].h_samp_factor = 2;
    cinfo.comp_info[0].v_samp_factor = 2;
    cinfo.comp_info[1].h_samp_factor = 1;
    cinfo.comp_info[1].v_samp_factor = 1;
    cinfo.comp_info[2].h_samp_factor = 1;
    cinfo.comp_info[2].v_samp_factor = 1;

    jpeg_set_quality(&cinfo, quality, TRUE);
    cinfo.dct_method = JDCT_FASTEST;

    jpeg_stdio_dest(&cinfo, fp);        // data written to file
    jpeg_start_compress(&cinfo, TRUE);

    for (j = 0; j < height; j += 16) {
        for (i = 0; i < 16; i++) {
            y[i] = image + width * (i + j);
            if (i % 2 == 0) {
                cb[i / 2] = image + width * height + width / 2 * ((i + j) / 2);
                cr[i / 2] = image + width * height + width * height / 4 + width / 2 * ((i + j) /2);
            }
        }
        jpeg_write_raw_data(&cinfo, data, 16);
    }

    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);
}


/* put_ppm_bgr24_file converts an greyscale image to a PPM image and writes
 * it to an already open file.
 * Inputs:
 * - image is the image in YUV420P format.
 * - width and height are the dimensions of the image
 * Output:
 * - The PPM is written directly to the file given by the file pointer fp
 * Returns nothing
 */
static void put_ppm_bgr24_file(FILE *picture, unsigned char *image, int width, int height)
{
    int x, y;
    unsigned char *l = image;
    unsigned char *u = image + width * height;
    unsigned char *v = u + (width * height) / 4;
    int r, g, b;
    int warningkiller;
    unsigned char rgb[3];
    
    /*    ppm header
     *    width height
     *    maxval
     */
    fprintf(picture, "P6\n");
    fprintf(picture, "%d %d\n", width, height);
    fprintf(picture, "%d\n", 255);
    for (y = 0; y < height; y++) {
        
        for (x = 0; x < width; x++) {
            r = 76283* (((int)*l) - 16) + 104595 * (((int)*u) - 128);
            g = 76283* (((int)*l) - 16)- 53281 * (((int)*u) - 128)-25625*(((int)*v)-128);
            b = 76283* (((int)*l) - 16) + 132252 * (((int)*v) - 128);
            r = r>>16;
            g = g>>16;
            b = b>>16;
            if (r < 0)
                r = 0;
            else if (r > 255)
                r = 255;
            if (g < 0)
                g = 0;
            else if (g > 255)
                g = 255;
            if (b < 0)
                b = 0;
            else if (b > 255)
                b = 255;

            rgb[0] = b;
            rgb[1] = g;
            rgb[2] = r;

            l++;
            if (x & 1) {
                u++;
                v++;
            }
            /* ppm is rgb not bgr */
            warningkiller = fwrite(rgb, 1, 3, picture);
        }
        if (y & 1) {
            u -= width / 2;
            v -= width / 2;
        }
    }
}
/* put_picture_mem is used for the webcam feature. Depending on the image type
 * (colour YUV420P or greyscale) the corresponding put_jpeg_X_memory function is called.
 * Inputs:
 * - cnt is the global context struct and only cnt->imgs.type is used.
 * - image_size is the size of the input image buffer
 * - *image points to the image buffer that contains the YUV420P or Grayscale image about to be put
 * - quality is the jpeg quality setting from the config file.
 * Output:
 * - **dest_image is a pointer to a pointer that points to the destination buffer in which the
 *   converted image it put
 * Function returns the dest_image_size if successful. Otherwise 0.
 */ 
int put_picture_memory(struct context *cnt, unsigned char* dest_image, int image_size,
                       unsigned char *image, int quality)
{
    switch (cnt->imgs.type) {
    case VIDEO_PALETTE_YUV420P:
        return put_jpeg_yuv420p_memory(dest_image, image_size, image,
                                       cnt->imgs.width, cnt->imgs.height, quality);
  //  case VIDEO_PALETTE_GREY:
   //     return put_jpeg_grey_memory(dest_image, image_size, image,
    //                                cnt->imgs.width, cnt->imgs.height, quality);
    default:
        motion_log(LOG_ERR, 0, "Unknow image type %d", cnt->imgs.type);            
    }

    return 0;
}

void put_picture_fd(struct context *cnt, FILE *picture, unsigned char *image, int quality)
{
    if (cnt->conf.ppm) {
        put_ppm_bgr24_file(picture, image, cnt->imgs.width, cnt->imgs.height);
    } else {
        switch (cnt->imgs.type) {
        case VIDEO_PALETTE_YUV420P:
            put_jpeg_yuv420p_file(picture, image, cnt->imgs.width, cnt->imgs.height, quality);
            break;
        case VIDEO_PALETTE_GREY:
        //    put_jpeg_grey_file(picture, image, cnt->imgs.width, cnt->imgs.height, quality);
            break;
        default :
            motion_log(LOG_ERR, 0, "Unknow image type %d", cnt->imgs.type);
        }
    }
}


void put_picture(struct context *cnt, char *file, unsigned char *image, int ftype)
{
    FILE *picture;

    picture = myfopen(file, "w");
    if (!picture) {
        /* Report to syslog - suggest solution if the problem is access rights to target dir */
        if (errno ==  EACCES) {
            motion_log(LOG_ERR, 1,
                       "Can't write picture to file %s - check access rights to target directory", file);
            motion_log(LOG_ERR, 1, "Thread is going to finish due to this fatal error");
            cnt->finish = 1;
            cnt->restart = 0;
            return;
        } else {
            /* If target dir is temporarily unavailable we may survive */
            motion_log(LOG_ERR, 1, "Can't write picture to file %s", file);
            return;
        }
    }

    put_picture_fd(cnt, picture, image, cnt->conf.quality);
    fclose(picture);
 //   event(cnt, EVENT_FILECREATE, NULL, file, (void *)(unsigned long)ftype, NULL);
	event_newfile(cnt, NULL, NULL, file, (void *)(unsigned long)ftype, NULL);

}

/* Get the pgm file used as fixed mask */
unsigned char *get_pgm(FILE *picture, int width, int height)
{
    int x = 0 ,y = 0, maxval;
    char line[256];
    unsigned char *image;

    line[255]=0;
    
    if (!fgets(line, 255, picture)) {
        motion_log(LOG_ERR, 1, "Could not read from ppm file");
        return NULL;
    }
    
    if (strncmp(line, "P5", 2)) {
        motion_log(LOG_ERR, 1, "This is not a ppm file, starts with '%s'", line);
        return NULL;
    }
    
    /* skip comment */
    line[0] = '#';
    while (line[0] == '#')
        if (!fgets(line, 255, picture))
            return NULL;

    /* check size */
    if (sscanf(line, "%d %d", &x, &y) != 2) {
        motion_log(LOG_ERR, 1, "Failed reading size in pgm file");
        return NULL;
    }
    
    if (x != width || y != height) {
        motion_log(LOG_ERR, 1, "Wrong image size %dx%d should be %dx%d", x, y, width, height);
        return NULL;
    }

    /* Maximum value */
    line[0] = '#';
    while (line[0] == '#')
        if (!fgets(line, 255, picture))
            return NULL;
    
    if (sscanf(line, "%d", &maxval) != 1) {
        motion_log(LOG_ERR, 1, "Failed reading maximum value in pgm file");
        return NULL;
    }
    
    /* read data */
    
    image = mymalloc(width * height);
    
    for (y = 0; y < height; y++) {
        if ((int)fread(&image[y * width], 1, width, picture) != width)
            motion_log(LOG_ERR, 1, "Failed reading image data from pgm file");
        
        for (x = 0; x < width; x++)
            image[y * width + x] = (int)image[y * width + x] * 255 / maxval;
        
    }    

    return image;
}

/* If a mask file is asked for but does not exist this function
 * creates an empty mask file in the right binary pgm format and
 * and the right size - easy to edit with Gimp or similar tool.
 */
void put_fixed_mask(struct context *cnt, const char *file)
{
    FILE *picture;

    picture = myfopen(file, "w");
    
    if (!picture) {
        /* Report to syslog - suggest solution if the problem is access rights to target dir */
        if (errno ==  EACCES) {
            motion_log(LOG_ERR, 1,
                       "can't write mask file %s - check access rights to target directory", file);
        } else {
            /* If target dir is temporarily unavailable we may survive */
            motion_log(LOG_ERR, 1, "can't write mask file %s", file);
        }
        return;
    }

    memset(cnt->imgs.out, 255, cnt->imgs.motionsize); /* initialize to unset */
    
    /* Write pgm-header */
    fprintf(picture, "P5\n");
    fprintf(picture, "%d %d\n", cnt->conf.width, cnt->conf.height);
    fprintf(picture, "%d\n", 255);
    
    /* write pgm image data at once */
    if ((int)fwrite(cnt->imgs.out, cnt->conf.width, cnt->conf.height, picture) != cnt->conf.height) {
        motion_log(LOG_ERR, 1, "Failed writing default mask as pgm file");
        return;
    }
    
    fclose(picture);

    motion_log(LOG_ERR, 0, "Creating empty mask %s",cnt->conf.mask_file);
    motion_log(LOG_ERR, 0, "Please edit this file and re-run motion to enable mask feature");
}
