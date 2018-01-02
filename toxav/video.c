/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "video.h"

#include "msi.h"
#include "ring_buffer.h"
#include "rtp.h"

#include "../toxcore/logger.h"
#include "../toxcore/network.h"

#include <assert.h>
#include <stdlib.h>

/*
  Soft deadline the decoder should attempt to meet, in "us" (microseconds). Set to zero for unlimited.
  By convention, the value 1 is used to mean "return as fast as possible."
*/
// TODO: don't hardcode this, let the application choose it
#define WANTED_MAX_DECODER_FPS (40)
#define MAX_DECODE_TIME_US (1000000 / WANTED_MAX_DECODER_FPS) // to allow x fps
/*
VPX_DL_REALTIME       (1)
deadline parameter analogous to VPx REALTIME mode.

VPX_DL_GOOD_QUALITY   (1000000)
deadline parameter analogous to VPx GOOD QUALITY mode.

VPX_DL_BEST_QUALITY   (0)
deadline parameter analogous to VPx BEST QUALITY mode.
*/

#define VP8E_SET_CPUUSED_VALUE (16)
/*
Codec control function to set encoder internal speed settings.
Changes in this value influences, among others, the encoder's selection of motion estimation methods.
Values greater than 0 will increase encoder speed at the expense of quality.

Note
    Valid range for VP8: -16..16
    Valid range for VP9: -8..8
 */

// zugzrev: this seems unrealistically high? And should anyway be set by the
// client?
#define VIDEO_BITRATE_INITIAL_VALUE 5000 // initialize encoder with this value. Target bandwidth to use for this stream, in kilobits per second.


#define VIDEO_DECODE_BUFFER_SIZE 5 // this buffer has normally max. 1 entry




void vc__init_encoder_cfg(Logger *log, vpx_codec_enc_cfg_t *cfg, int16_t kf_max_dist)
{

    vpx_codec_err_t rc;

    if (VPX_ENCODER_USED == VPX_VP8_CODEC) {
        LOGGER_WARNING(log, "Using VP8 codec for encoder (1)");
        rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE_VP8, cfg, 0);
    } else {
        LOGGER_WARNING(log, "Using VP9 codec for encoder (1)");
        rc = vpx_codec_enc_config_default(VIDEO_CODEC_ENCODER_INTERFACE_VP9, cfg, 0);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "vc__init_encoder_cfg:Failed to get config: %s", vpx_codec_err_to_string(rc));
    }

    cfg->rc_target_bitrate =
        VIDEO_BITRATE_INITIAL_VALUE; /* Target bandwidth to use for this stream, in kilobits per second */
    cfg->g_w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    cfg->g_h = VIDEO_CODEC_DECODER_MAX_HEIGHT;
    cfg->g_pass = VPX_RC_ONE_PASS;



    /* zoff (in 2017) */
    cfg->g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg->g_lag_in_frames = 0;
    /* Allow lagged encoding
     *
     * If set, this value allows the encoder to consume a number of input
     * frames before producing output frames. This allows the encoder to
     * base decisions for the current frame on future frames. This does
     * increase the latency of the encoding pipeline, so it is not appropriate
     * in all situations (ex: realtime encoding).
     *
     * Note that this is a maximum value -- the encoder may produce frames
     * sooner than the given limit. Set this value to 0 to disable this
     * feature.
     */
    cfg->kf_min_dist = 0;
    cfg->kf_mode = VPX_KF_AUTO; // Encoder determines optimal placement automatically
    cfg->rc_end_usage = VPX_VBR; // what quality mode?

    /*
     VPX_VBR    Variable Bit Rate (VBR) mode
     VPX_CBR    Constant Bit Rate (CBR) mode
     VPX_CQ     Constrained Quality (CQ) mode -> give codec a hint that we may be on low bandwidth connection
     VPX_Q    Constant Quality (Q) mode
     */
    if (kf_max_dist > 1) {
        cfg->kf_max_dist = kf_max_dist; // a full frame every x frames minimum (can be more often, codec decides automatically)
        LOGGER_WARNING(log, "kf_max_dist=%d (1)", cfg->kf_max_dist);
    } else {
        cfg->kf_max_dist = VPX_MAX_DIST_START;
        LOGGER_WARNING(log, "kf_max_dist=%d (2)", cfg->kf_max_dist);
    }

    if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
        cfg->kf_max_dist = VIDEO__VP9_KF_MAX_DIST;
        LOGGER_WARNING(log, "kf_max_dist=%d (3)", cfg->kf_max_dist);
    }

    cfg->g_threads = VPX_MAX_ENCODER_THREADS; // Maximum number of threads to use

    // cfg->g_timebase.num = 1;
    // cfg->g_timebase.den = 60; // 60 fps

    cfg->rc_resize_allowed = 1; // allow encoder to resize to smaller resolution
    // cfg->rc_dropframe_thresh = 10;

    cfg->rc_resize_up_thresh = 40;
    cfg->rc_resize_down_thresh = 5;

#if 0
    /* Highest-resolution encoder settings */
    cfg->rc_dropframe_thresh = 0;
    cfg->rc_resize_allowed = 0;
    cfg->rc_min_quantizer = 2;
    cfg->rc_max_quantizer = 56;
    cfg->rc_undershoot_pct = 100;
    cfg->rc_overshoot_pct = 15;
    cfg->rc_buf_initial_sz = 500;
    cfg->rc_buf_optimal_sz = 600;
    cfg->rc_buf_sz = 1000;
#endif

}



VCSession *vc_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data)
{
    VCSession *vc = (VCSession *)calloc(sizeof(VCSession), 1);
    vpx_codec_err_t rc;

    if (!vc) {
        LOGGER_WARNING(log, "Allocation failed! Application might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(vc->queue_mutex) != 0) {
        LOGGER_WARNING(log, "Failed to create recursive mutex!");
        free(vc);
        return NULL;
    }

    if (!(vc->vbuf_raw = rb_new(VIDEO_DECODE_BUFFER_SIZE))) {
        goto BASE_CLEANUP;
    }





    /*
    VPX_CODEC_USE_FRAME_THREADING
       Enable frame-based multi-threading

    VPX_CODEC_USE_ERROR_CONCEALMENT
       Conceal errors in decoded frames
    */
    vpx_codec_dec_cfg_t  dec_cfg;
    dec_cfg.threads = VPX_MAX_DECODER_THREADS; // Maximum number of threads to use
    dec_cfg.w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    dec_cfg.h = VIDEO_CODEC_DECODER_MAX_HEIGHT;

    if (VPX_DECODER_USED == VPX_VP8_CODEC) {
        LOGGER_WARNING(log, "Using VP8 codec for decoder (0)");

        rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                VPX_CODEC_USE_FRAME_THREADING | VPX_CODEC_USE_POSTPROC);

        if (rc == VPX_CODEC_INCAPABLE) {
            LOGGER_WARNING(log, "Postproc not supported by this decoder (0)");
            rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg, VPX_CODEC_USE_FRAME_THREADING);
        }

    } else {
        LOGGER_WARNING(log, "Using VP9 codec for decoder (0)");
        rc = vpx_codec_dec_init(vc->decoder, VIDEO_CODEC_DECODER_INTERFACE_VP9, &dec_cfg, VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Init video_decoder failed: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP;
    }



    if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 1) {
        // vp8_postproc_cfg_t pp = {VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_MFQE, 4, 0};
        vp8_postproc_cfg_t pp = {VP8_DEBLOCK , 1, 0};
        vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(log, "Failed to turn on postproc");
        } else {
            LOGGER_WARNING(log, "turn on postproc: OK");
        }
    } else {
        vp8_postproc_cfg_t pp = {0, 0, 0};
        vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(log, "Failed to turn OFF postproc");
        } else {
            LOGGER_WARNING(log, "Disable postproc: OK");
        }
    }











    /* Set encoder to some initial values
     */
    vpx_codec_enc_cfg_t  cfg;
    vc__init_encoder_cfg(log, &cfg, 1);

    if (VPX_ENCODER_USED == VPX_VP8_CODEC) {
        LOGGER_WARNING(log, "Using VP8 codec for encoder (0.1)");
        rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg, VPX_CODEC_USE_FRAME_THREADING);
    } else {
        LOGGER_WARNING(log, "Using VP9 codec for encoder (0.1)");
        rc = vpx_codec_enc_init(vc->encoder, VIDEO_CODEC_ENCODER_INTERFACE_VP9, &cfg, VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }







    /*
    Codec control function to set encoder internal speed settings.
    Changes in this value influences, among others, the encoder's selection of motion estimation methods.
    Values greater than 0 will increase encoder speed at the expense of quality.

    Note:
      Valid range for VP8: -16..16
      Valid range for VP9: -8..8
    */

    int cpu_used_value = VP8E_SET_CPUUSED_VALUE;

    if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
        if ((cpu_used_value < -8) || (cpu_used_value > 8)) {
            cpu_used_value = 8; // set to default (fastest) value
        }
    }

    rc = vpx_codec_control(vc->encoder, VP8E_SET_CPUUSED, cpu_used_value);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    }

    /*
    VP9E_SET_TILE_COLUMNS

    Codec control function to set number of tile columns.

    In encoding and decoding, VP9 allows an input image frame be partitioned
    into separated vertical tile columns, which can be encoded or decoded independently.
    This enables easy implementation of parallel encoding and decoding. This control requests
    the encoder to use column tiles in encoding an input frame, with number of tile columns
    (in Log2 unit) as the parameter: 0 = 1 tile column 1 = 2 tile columns
    2 = 4 tile columns ..... n = 2**n tile columns The requested tile columns will
    be capped by encoder based on image size limitation (The minimum width of a
    tile column is 256 pixel, the maximum is 4096).

    By default, the value is 0, i.e. one single column tile for entire image.

    Supported in codecs: VP9
     */

    if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
        rc = vpx_codec_control(vc->encoder, VP9E_SET_TILE_COLUMNS, VIDEO__VP9E_SET_TILE_COLUMNS);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(vc->encoder);
            goto BASE_CLEANUP_1;
        }
    }


    if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
        if (1 == 2) {
            rc = vpx_codec_control(vc->encoder, VP9E_SET_LOSSLESS, 1);

            LOGGER_WARNING(vc->log, "setting VP9 lossless video quality(2): ON");

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(vc->encoder);
                goto BASE_CLEANUP_1;
            }
        } else {
            rc = vpx_codec_control(vc->encoder, VP9E_SET_LOSSLESS, 0);

            LOGGER_WARNING(vc->log, "setting VP9 lossless video quality(2): OFF");

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(vc->encoder);
                goto BASE_CLEANUP_1;
            }
        }
    }



    /*
    VPX_CTRL_USE_TYPE(VP8E_SET_NOISE_SENSITIVITY,  unsigned int)
    control function to set noise sensitivity
      0: off, 1: OnYOnly, 2: OnYUV, 3: OnYUVAggressive, 4: Adaptive
    */
    /*
      rc = vpx_codec_control(vc->encoder, VP8E_SET_NOISE_SENSITIVITY, 2);

      if (rc != VPX_CODEC_OK) {
          LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
          vpx_codec_destroy(vc->encoder);
          goto BASE_CLEANUP_1;
      }
     */



    vc->linfts = current_time_monotonic();
    vc->lcfd = 60;
    vc->vcb.first = cb;
    vc->vcb.second = cb_data;
    vc->friend_number = friend_number;
    vc->av = av;
    vc->log = log;

    return vc;

BASE_CLEANUP_1:
    vpx_codec_destroy(vc->decoder);
BASE_CLEANUP:
    pthread_mutex_destroy(vc->queue_mutex);
    rb_kill((RingBuffer *)vc->vbuf_raw);
    free(vc);
    return NULL;
}

void vc_kill(VCSession *vc)
{
    if (!vc) {
        return;
    }

    vpx_codec_destroy(vc->encoder);
    vpx_codec_destroy(vc->decoder);

    void *p;
    uint8_t dummy;

    while (rb_read((RingBuffer *)vc->vbuf_raw, &p, &dummy)) {
        free(p);
    }

    rb_kill((RingBuffer *)vc->vbuf_raw);

    pthread_mutex_destroy(vc->queue_mutex);

    LOGGER_DEBUG(vc->log, "Terminated video handler: %p", vc);
    free(vc);
}



void video_switch_decoder(VCSession *vc)
{


    /*
    vpx_codec_err_t vpx_codec_peek_stream_info  (   vpx_codec_iface_t *     iface,
            const uint8_t *     data,
            unsigned int    data_sz,
            vpx_codec_stream_info_t *   si
        )

    Parse stream info from a buffer.
    Performs high level parsing of the bitstream. Construction of a decoder context is not necessary.
    Can be used to determine if the bitstream is of the proper format, and to extract information from the stream.
    */


    vpx_codec_err_t rc;

    // Zoff --
    if (vc->is_using_vp9 == 1) {
        vc->is_using_vp9 = 0;
    } else {
        vc->is_using_vp9 = 1;
    }

    // Zoff --


    vpx_codec_ctx_t new_d;

    LOGGER_WARNING(vc->log, "Switch:Re-initializing DEcoder to: %d", (int)vc->is_using_vp9);

    vpx_codec_dec_cfg_t dec_cfg;
    dec_cfg.threads = VPX_MAX_DECODER_THREADS; // Maximum number of threads to use
    dec_cfg.w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    dec_cfg.h = VIDEO_CODEC_DECODER_MAX_HEIGHT;

    if (vc->is_using_vp9 == 0) {
        rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg,
                                VPX_CODEC_USE_FRAME_THREADING | VPX_CODEC_USE_POSTPROC);

        if (rc == VPX_CODEC_INCAPABLE) {
            LOGGER_WARNING(vc->log, "Postproc not supported by this decoder");
            rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP8, &dec_cfg, VPX_CODEC_USE_FRAME_THREADING);
        }

    } else {
        rc = vpx_codec_dec_init(&new_d, VIDEO_CODEC_DECODER_INTERFACE_VP9, &dec_cfg, VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(vc->log, "Failed to Re-initialize decoder: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(&new_d);
        return;
    }


    if (VIDEO__VP8_DECODER_POST_PROCESSING_ENABLED == 1) {
        // vp8_postproc_cfg_t pp = {VP8_DEBLOCK | VP8_DEMACROBLOCK | VP8_MFQE, 4, 0};
        vp8_postproc_cfg_t pp = {VP8_DEBLOCK , 1, 0};
        vpx_codec_err_t cc_res = vpx_codec_control(&new_d, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(vc->log, "Failed to turn on postproc");
        } else {
            LOGGER_WARNING(vc->log, "turn on postproc: OK");
        }
    } else {
        vp8_postproc_cfg_t pp = {0, 0, 0};
        vpx_codec_err_t cc_res = vpx_codec_control(&new_d, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(vc->log, "Failed to turn OFF postproc");
        } else {
            LOGGER_WARNING(vc->log, "Disable postproc: OK");
        }
    }


    // now replace the current decoder
    vpx_codec_destroy(vc->decoder);
    memcpy(vc->decoder, &new_d, sizeof(new_d));

    LOGGER_ERROR(vc->log, "Re-initialize decoder OK: %s", vpx_codec_err_to_string(rc));

}


void vc_iterate(VCSession *vc)
{
    if (!vc) {
        return;
    }

    struct RTPMessage *p;

    vpx_codec_err_t rc;

    pthread_mutex_lock(vc->queue_mutex);

    uint8_t data_type;

    uint32_t full_data_len;

    if (rb_read((RingBuffer *)vc->vbuf_raw, (void **)&p, &data_type)) {
        pthread_mutex_unlock(vc->queue_mutex);

        const struct RTPHeaderV3 *header_v3 = (void *) & (p->header);
        LOGGER_DEBUG(vc->log, "vc_iterate:00:pv=%d", (uint8_t)header_v3->protocol_version);

        if (((uint8_t)header_v3->protocol_version) == 3) {
            full_data_len = header_v3->data_length_full;
            LOGGER_DEBUG(vc->log, "vc_iterate:001:full_data_len=%d", (int)full_data_len);
        } else {
            full_data_len = p->len;
            LOGGER_DEBUG(vc->log, "vc_iterate:002");
        }

        LOGGER_DEBUG(vc->log, "vc_iterate: rb_read p->len=%d data_type=%d", (int)full_data_len, (int)data_type);
        LOGGER_DEBUG(vc->log, "vc_iterate: rb_read rb size=%d", (int)rb_size((RingBuffer *)vc->vbuf_raw));


        rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, NULL, MAX_DECODE_TIME_US);

        if (rc != VPX_CODEC_OK) {
            // zugzrev: no #defines for return values 5 and 7?
            if (rc == 5) { // Bitstream not supported by this decoder
                LOGGER_WARNING(vc->log, "Switching VPX Decoder");
                video_switch_decoder(vc);
            } else if (rc == 7) {
                LOGGER_WARNING(vc->log, "Corrupt frame detected: data size=%d start byte=%d end byte=%d",
                               (int)full_data_len, (int)p->data[0], (int)p->data[full_data_len - 1]);
            } else {
                LOGGER_ERROR(vc->log, "Error decoding video: %d %s", (int)rc, vpx_codec_err_to_string(rc));
            }

            rc = vpx_codec_decode(vc->decoder, p->data, full_data_len, NULL, MAX_DECODE_TIME_US);

            if (rc != 5) {
                LOGGER_ERROR(vc->log, "There is still an error decoding video: %d %s", (int)rc, vpx_codec_err_to_string(rc));
            }
        }

        if (rc == VPX_CODEC_OK) {
            free(p);


            /* Play decoded images */
            vpx_codec_iter_t iter = NULL;
            vpx_image_t *dest = NULL;

            while ((dest = vpx_codec_get_frame(vc->decoder, &iter)) != NULL) {
                if (vc->vcb.first) {
                    vc->vcb.first(vc->av, vc->friend_number, dest->d_w, dest->d_h,
                                  (const uint8_t *)dest->planes[0], (const uint8_t *)dest->planes[1], (const uint8_t *)dest->planes[2],
                                  dest->stride[0], dest->stride[1], dest->stride[2], vc->vcb.second);
                }

                vpx_img_free(dest); // is this needed? none of the VPx examples show that
            }
        } else {
            free(p);
        }

        return;
    } else {
        // no frame data available
        // LOGGER_WARNING(vc->log, "Error decoding video: rb_read");
    }

    pthread_mutex_unlock(vc->queue_mutex);
}


int vc_queue_message(void *vcp, struct RTPMessage *msg)
{
    /* This function is called with complete messages
     * they have already been assembled.
     * this function gets called from handle_rtp_packet() and handle_rtp_packet_v3()
     */
    if (!vcp || !msg) {
        return -1;
    }

    VCSession *vc = (VCSession *)vcp;

    // const struct RTPHeader *header = (void *)&(msg->header);
    const struct RTPHeaderV3 *header_v3 = (void *) & (msg->header);

    if (msg->header.pt == (rtp_TypeVideo + 2) % 128) {
        LOGGER_WARNING(vc->log, "Got dummy!");
        free(msg);
        return 0;
    }

    if (msg->header.pt != rtp_TypeVideo % 128) {
        LOGGER_WARNING(vc->log, "Invalid payload type! pt=%d", (int)msg->header.pt);
        free(msg);
        return -1;
    }

    pthread_mutex_lock(vc->queue_mutex);

    if ((((uint8_t)header_v3->protocol_version) == 3) &&
            (((uint8_t)header_v3->pt) == (rtp_TypeVideo % 128))
       ) {
        LOGGER_DEBUG(vc->log, "rb_write msg->len=%d b0=%d b1=%d", (int)msg->len, (int)msg->data[0], (int)msg->data[1]);
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, (uint8_t)header_v3->is_keyframe));
    } else {
        free(rb_write((RingBuffer *)vc->vbuf_raw, msg, 0));
    }


    /* Calculate time it took for peer to send us this frame */
    uint32_t t_lcfd = current_time_monotonic() - vc->linfts;
    vc->lcfd = t_lcfd > 100 ? vc->lcfd : t_lcfd;
    vc->linfts = current_time_monotonic();

    pthread_mutex_unlock(vc->queue_mutex);

    return 0;
}

int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist)
{
    if (!vc) {
        return -1;
    }

    // zugzrev: could call it cfg (no actual conflict)
    vpx_codec_enc_cfg_t cfg2 = *vc->encoder->config.enc;
    vpx_codec_err_t rc;

    if (cfg2.rc_target_bitrate == bit_rate && cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1) {
        return 0; /* Nothing changed */
    }

    if (cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1) {
        /* Only bit rate changed */

        LOGGER_INFO(vc->log, "bitrate change from: %u to: %u", (uint32_t)cfg2.rc_target_bitrate, (uint32_t)bit_rate);

        cfg2.rc_target_bitrate = bit_rate;

        rc = vpx_codec_enc_config_set(vc->encoder, &cfg2);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            return -1;
        }
    } else {
        /* Resolution is changed, must reinitialize encoder since libvpx v1.4 doesn't support
         * reconfiguring encoder to use resolutions greater than initially set.
         */

        LOGGER_DEBUG(vc->log, "Have to reinitialize vpx encoder on session %p", vc);


        vpx_codec_ctx_t new_c;
        vpx_codec_enc_cfg_t cfg;
        vc__init_encoder_cfg(vc->log, &cfg, kf_max_dist);

        cfg.rc_target_bitrate = bit_rate;
        cfg.g_w = width;
        cfg.g_h = height;


        if (VPX_ENCODER_USED == VPX_VP8_CODEC) {
            LOGGER_WARNING(vc->log, "Using VP8 codec for encoder");
            rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE_VP8, &cfg, VPX_CODEC_USE_FRAME_THREADING);
        } else {
            LOGGER_WARNING(vc->log, "Using VP9 codec for encoder");
            rc = vpx_codec_enc_init(&new_c, VIDEO_CODEC_ENCODER_INTERFACE_VP9, &cfg, VPX_CODEC_USE_FRAME_THREADING);
        }

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
            return -1;
        }


        int cpu_used_value = VP8E_SET_CPUUSED_VALUE;

        if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
            if ((cpu_used_value < -8) || (cpu_used_value > 8)) {
                cpu_used_value = 8; // set to default (fastest) value
            }
        }

        rc = vpx_codec_control(&new_c, VP8E_SET_CPUUSED, cpu_used_value);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(&new_c);
            return -1;
        }

        if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
            rc = vpx_codec_control(&new_c, VP9E_SET_TILE_COLUMNS, VIDEO__VP9E_SET_TILE_COLUMNS);

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                vpx_codec_destroy(&new_c);
                return -1;
            }
        }

        if (VPX_ENCODER_USED == VPX_VP9_CODEC) {
            if (1 == 2) {
                LOGGER_WARNING(vc->log, "setting VP9 lossless video quality: ON");

                rc = vpx_codec_control(&new_c, VP9E_SET_LOSSLESS, 1);

                if (rc != VPX_CODEC_OK) {
                    LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                    vpx_codec_destroy(&new_c);
                    return -1;
                }
            } else {
                LOGGER_WARNING(vc->log, "setting VP9 lossless video quality: OFF");

                rc = vpx_codec_control(&new_c, VP9E_SET_LOSSLESS, 0);

                if (rc != VPX_CODEC_OK) {
                    LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
                    vpx_codec_destroy(&new_c);
                    return -1;
                }
            }
        }


        vpx_codec_destroy(vc->encoder);
        memcpy(vc->encoder, &new_c, sizeof(new_c));
    }

    return 0;
}


