/*
 * Intel NUC LED Control Driver
 *
 * Copyright (C) 2018 Teruaki Kawashima
 *
 * Adapted some from https://github.com/nomego/intel_nuc_led
 * Copyright (C) 2018 Patrik Kullman
 *
 * Forked from https://github.com/milesp20/intel_nuc_led
 * Copyright (C) 2017 Miles Peterson
 *
 * Portions based on asus-wmi.c:
 * Copyright (C) 2010 Intel Corporation.
 * Copyright (C) 2010-2011 Corentin Chary <corentin.chary@gmail.com>
 *
 * Portions based on acpi_call.c:
 * Copyright (C) 2010: Michal Kottman
 *
 * Based on Intel Article ID 000023426
 * http://www.intel.com/content/www/us/en/support/boards-and-kits/intel-nuc-kits/000023426.html
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/acpi.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>

MODULE_AUTHOR("Teruaki Kawashima");
MODULE_DESCRIPTION("Intel NUC LED Control WMI Driver");
MODULE_LICENSE("GPL");
ACPI_MODULE_NAME("NUC_LED");

static unsigned int nuc_led_perms __read_mostly = S_IRUGO | S_IWUSR | S_IWGRP;
static unsigned int nuc_led_uid __read_mostly;
static unsigned int nuc_led_gid __read_mostly;

module_param(nuc_led_perms, uint, S_IRUGO | S_IWUSR | S_IWGRP);
module_param(nuc_led_uid, uint, 0);
module_param(nuc_led_gid, uint, 0);

MODULE_PARM_DESC(nuc_led_perms, "permissions on /proc/acpi/nuc_led");
MODULE_PARM_DESC(nuc_led_uid, "default owner of /proc/acpi/nuc_led");
MODULE_PARM_DESC(nuc_led_gid, "default owning group of /proc/acpi/nuc_led");

/* Intel NUC WMI GUID */
#define NUCLED_WMI_MGMT_GUID            "8C5DA44C-CDC3-46b3-8619-4E26D34390B7"
MODULE_ALIAS("wmi:" NUCLED_WMI_MGMT_GUID);

/* LED Control Method ID */
#define NUCLED_WMI_METHODID_GETSTATE    0x01
#define NUCLED_WMI_METHODID_SETSTATE    0x02
#define NUCLED_WMI_METHODID_NEWGETLEDSTATUS                     0x04
#define NUCLED_WMI_METHODID_SETVALUEINDICATOROPTIONLEDTYPE      0x06

/* NUCLED_WMI_METHODID_NEWGETLEDSTATUS arguments */
#define NUCLED_WMI_METHODARG_GETCURRENTINDICATOR        0x00

/* LED Identifiers */
#define NUCLED_WMI_POWER_LED_ID         0x00
#define NUCLED_WMI_HDD_LED_ID           0x01
#define NUCLED_WMI_RING_LED_ID          0x07

/* LED Color Types */
#define NUCLED_WMI_TYPE_BLUE_AMBER      0x01
#define NUCLED_WMI_TYPE_BLUE_WHITE      0x02
#define NUCLED_WMI_TYPE_RGB             0x03

/* Indicator options / usage types */
#define NUCLED_WMI_USAGE_POWER_STATE   0x00
#define NUCLED_WMI_USAGE_HDD_ACTIVITY  0x01
#define NUCLED_WMI_USAGE_SOFTWARE      0x04
#define NUCLED_WMI_USAGE_DISABLE       0x06

/* Return codes */
#define NUCLED_WMI_RETURN_SUCCESS       0x00
#define NUCLED_WMI_RETURN_NOSUPPORT     0xE1
#define NUCLED_WMI_RETURN_UNDEFINED     0xE2
#define NUCLED_WMI_RETURN_NORESPONSE    0xE3
#define NUCLED_WMI_RETURN_BADPARAM      0xE4
#define NUCLED_WMI_RETURN_UNEXPECTED    0xEF

/* Blinking behavior */
#define NUCLED_WMI_BLINK_SOLID          0x00
#define NUCLED_WMI_BLINK_BREATHING      0x01
#define NUCLED_WMI_BLINK_PULSING        0x02

/* HDD behavior */
#define NUCLED_WMI_HDD_ACTIVE_ON        0x00
#define NUCLED_WMI_HDD_ACTIVE_OFF       0x01

/* Colors */
#define NUCLED_WMI_COLOR_DISABLE        0x00
#define NUCLED_WMI_COLOR_BLUE           0x01
#define NUCLED_WMI_COLOR_AMBER          0x02
#define NUCLED_WMI_COLOR_WHITE          0x02

extern struct proc_dir_entry *acpi_root_dir;

struct led_new_gen_args {
    u8 arg0;
    u8 arg1;
    u8 arg2;
    u8 arg3;
} __packed;

struct led_new_gen_result {
    u8 code;
    u8 value;
} __packed;

struct led_state {
    u8 led_id;
    u8 color_type;
    u8 result_code;
    u8 usage_type;
    u8 brightness;
    u8 blink_behavior;
    u8 blink_length;
    u8 hdd_behavior;
    u8 color[3];
} __packed;

#define BUFFER_SIZE 512
static char result_buffer[BUFFER_SIZE];

/* New Get LED status */
static int nuc_led_new_get_led_status(u8 arg0, u8 arg1, u8 arg2, u8 arg3, struct led_new_gen_result *result)
{
    struct led_new_gen_args args = {
        .arg0 = arg0,
        .arg1 = arg1,
        .arg2 = arg2,
        .arg3 = arg3,
    };
    struct acpi_buffer input;
    struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
    acpi_status status;
    union acpi_object *obj;

    input.length = (acpi_size) sizeof(args);
    input.pointer = &args;

    // Per Intel docs, first instance is used (instance is indexed from 0)
    status = wmi_evaluate_method(NUCLED_WMI_MGMT_GUID, 0,
                                 NUCLED_WMI_METHODID_NEWGETLEDSTATUS,
                                 &input, &output);

    if (ACPI_FAILURE(status)) {
        ACPI_EXCEPTION((AE_INFO, status, "wmi_evaluate_method"));
        return -EIO;
    }

    // Always returns a buffer
    obj = (union acpi_object *)output.pointer;
    if (obj) {
        result->code  = obj->buffer.pointer[0];
        result->value = obj->buffer.pointer[1];
    } else {
        result->code  = NUCLED_WMI_RETURN_UNEXPECTED;
        result->value = 0xff;
    }
    kfree(obj);

    return 0;
}

static int nuc_led_new_set_indicator_option(u8 arg0, u8 arg1, u8 arg2, u8 arg3, struct led_new_gen_result *result)
{
    struct led_new_gen_args args = {
        .arg0 = arg0,
        .arg1 = arg1,
        .arg2 = arg2,
        .arg3 = arg3,
    };
    struct acpi_buffer input;
    struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
    acpi_status status;
    union acpi_object *obj;

    input.length = (acpi_size) sizeof(args);
    input.pointer = &args;

    // Per Intel docs, first instance is used (instance is indexed from 0)
    status = wmi_evaluate_method(NUCLED_WMI_MGMT_GUID, 0,
                                 NUCLED_WMI_METHODID_SETVALUEINDICATOROPTIONLEDTYPE,
                                 &input, &output);

    if (ACPI_FAILURE(status)) {
        ACPI_EXCEPTION((AE_INFO, status, "wmi_evaluate_method"));
        return -EIO;
    }

    // Always returns a buffer
    obj = (union acpi_object *)output.pointer;
    result->code  = obj->buffer.pointer[0];
    result->value = 0;
    kfree(obj);

    return 0;
}

/* Get LED state */
static int nuc_led_get_state(struct led_state *state)
{
    const u8 led_id = state->led_id;
    struct led_new_gen_result result;
    u8 usage_type;
    int ret ;

    ret = nuc_led_new_get_led_status(NUCLED_WMI_METHODARG_GETCURRENTINDICATOR,
                                     led_id, 0, 0, &result);
    if (ret != 0) {
        return ret;
    }

    // it seems that only current indicator is available.
    state->result_code = result.code;
    if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
        return ret;
    }

    usage_type = state->usage_type = result.value;

    return 0;
}

/* Set LED state */
static int nuc_led_set_state(struct led_state *state)
{
    const u8 led_id = state->led_id;
    const u8 usage_type = state->usage_type;
    struct led_new_gen_result result;
    int ret, i;

    ret = nuc_led_new_get_led_status(NUCLED_WMI_METHODARG_GETCURRENTINDICATOR,
                                     led_id, 0, 0, &result);
    if (ret != 0) {
        return ret;
    }

    state->result_code = result.code;
    if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
        return 0;
    }

    if (usage_type == NUCLED_WMI_USAGE_POWER_STATE || usage_type == NUCLED_WMI_USAGE_SOFTWARE) {
        ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                               0, state->brightness, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set brightness failed: %02X\n", result.code);
        }

        ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                               1, state->blink_behavior, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set blink_behavior failed: %02X\n", result.code);
        }

        ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                               2, state->blink_length, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set blink_length failed: %02X\n", result.code);
        }

        for (i = 0; i < 3; i++) {
            ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                                   3+i, state->color[i], &result);
            if (ret != 0) {
                return ret;
            }
        }
    } else if (usage_type == NUCLED_WMI_USAGE_HDD_ACTIVITY) {
        ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                               0, state->brightness, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set brightness failed: %02X\n", result.code);
        }

        for (i = 0; i < 3; i++) {
            ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                                   1+i, state->color[i], &result);
            if (ret != 0) {
                return ret;
            }
        }

        ret = nuc_led_new_set_indicator_option(led_id, usage_type,
                                               4, state->hdd_behavior, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set hdd_behavior failed: %02X\n", result.code);
        }
    } else if (usage_type == NUCLED_WMI_USAGE_DISABLE) {
        ret = nuc_led_new_set_indicator_option(led_id, usage_type, 0, 0, &result);
        if (ret != 0) {
            return ret;
        }
        if (result.code != NUCLED_WMI_RETURN_SUCCESS) {
            state->result_code = result.code;
            pr_warn("set brightness failed: %02X\n", result.code);
        }
    }

    return 0;
}

static const char *usage_type_str(u8 usage_type)
{
    switch (usage_type) {
    case NUCLED_WMI_USAGE_POWER_STATE:  return "Power";
    case NUCLED_WMI_USAGE_HDD_ACTIVITY: return "HDD";
    case NUCLED_WMI_USAGE_SOFTWARE:     return "SW control";
    case NUCLED_WMI_USAGE_DISABLE:      return "Disabled";
    default: return "Unknown";
    }
}

static int sprint_led_status(char *buffer, int status, const struct led_state *state)
{
    if (status) {
        return sprintf(buffer, "WMI call failed\n");
    } else if (state->result_code != NUCLED_WMI_RETURN_SUCCESS) {
        return sprintf(buffer, "WMI call returned error (%02X)\n", state->result_code);
    } else {
        return sprintf(buffer, "mode:%s\n", usage_type_str(state->usage_type));
    }
}

static ssize_t acpi_proc_read(struct file *filp, char __user *buff,
    size_t count, loff_t *off)
{
    ssize_t ret;
    int status_power;
    int status_hdd;
    int status_ring;
    struct led_state state_power;
    struct led_state state_hdd;
    struct led_state state_ring;
    int len;

    // Get statuses from WMI interface
    state_power.led_id = NUCLED_WMI_POWER_LED_ID;
    state_power.color_type = NUCLED_WMI_TYPE_BLUE_AMBER;
    status_power = nuc_led_get_state(&state_power);
    if (status_power) {
        pr_warn("Unable to get NUC power LED state\n");
    }

    state_hdd.led_id = NUCLED_WMI_HDD_LED_ID;
    state_hdd.color_type = NUCLED_WMI_TYPE_BLUE_AMBER;
    status_hdd = nuc_led_get_state(&state_hdd);
    if (status_hdd) {
        pr_warn("Unable to get NUC HDD LED state\n");
    }

    state_ring.led_id = NUCLED_WMI_RING_LED_ID;
    state_ring.color_type = NUCLED_WMI_TYPE_RGB;
    status_ring = nuc_led_get_state(&state_ring);
    if (status_ring) {
        pr_warn("Unable to get NUC ring LED state\n");
    }

    // Clear buffer
    len = 0;
    memset(result_buffer, 0, BUFFER_SIZE);

    // Process state for power LED
    len += sprintf(result_buffer + len, "Power LED: ");
    len += sprint_led_status(result_buffer + len, status_power, &state_power);

    // Process state for HDD LED
    len += sprintf(result_buffer + len, "HDD LED  : ");
    len += sprint_led_status(result_buffer + len, status_hdd, &state_hdd);

    // Process state for Ring LED
    len += sprintf(result_buffer + len, "Ring LED : ");
    len += sprint_led_status(result_buffer + len, status_ring, &state_ring);

    // Return buffer via proc
    ret = simple_read_from_buffer(buff, count, off, result_buffer, len);

    return ret;
}

static int parse_input(char *input, size_t len, struct led_state *state)
{
    int i = 0;
    char *arg, *sep = input;

    // Strip new line
    input[len] = '\0';
    if (input[len-1] == '\n') {
        input[len-1] = '\0';
        len--;
    }
    state->led_id = 0xff;

    // it seems that only power button as power indicator can be controlled...
    while ((arg = strsep(&sep, ",")) && *arg) {
        switch (i) {
        case 0:
            // Target LED (power,hdd)
            if (!strcmp(arg, "power")) {
                state->led_id = NUCLED_WMI_POWER_LED_ID;
                state->color_type = NUCLED_WMI_TYPE_BLUE_AMBER;
            } else {
                pr_warn("invalid argument for target led\n");
                pr_warn("only power is supported as target led\n");
                return -EINVAL;
            }
            break;
        case 1:
            // Usage Type (power,hdd,sw,disable)
            if (!strcmp(arg, "power")) {
                state->usage_type = NUCLED_WMI_USAGE_POWER_STATE;
            } else {
                pr_warn("invalid argument for usage type\n");
                pr_warn("only power is supported as usage type\n");
                return -EINVAL;
            }
            break;
        case 2:
            // brightness (0 - 100)
            state->brightness = simple_strtol(arg, NULL, 10);
            if (state->brightness < 0 || state->brightness > 100) {
                pr_warn("invalid argument for brightness\n");
                return -EINVAL;
            }
            break;
        case 3:
            if (state->usage_type == NUCLED_WMI_USAGE_POWER_STATE || state->usage_type == NUCLED_WMI_USAGE_SOFTWARE) {
                // blink behavior (solid,breathing,pulsing)
                if (!strcmp(arg, "solid")) {
                    state->blink_behavior = NUCLED_WMI_BLINK_SOLID;
                } else if (!strcmp(arg, "breathing")) {
                    state->blink_behavior = NUCLED_WMI_BLINK_BREATHING;
                } else if (!strcmp(arg, "pulsing")) {
                    state->blink_behavior = NUCLED_WMI_BLINK_PULSING;
                } else {
                    pr_warn("invalid argument for blink behavior\n");
                    return -EINVAL;
                }
            } else if (state->usage_type == NUCLED_WMI_USAGE_HDD_ACTIVITY) {
                if (!strcmp(arg, "activeon")) {
                    state->hdd_behavior = NUCLED_WMI_HDD_ACTIVE_ON;
                } else if (!strcmp(arg, "activeoff")) {
                    state->hdd_behavior = NUCLED_WMI_HDD_ACTIVE_OFF;
                } else {
                    pr_warn("invalid argument for hdd activity behavior\n");
                    return -EINVAL;
                }
            }
            break;
        case 4:
            // blink length (1 - 9)
            if (state->usage_type == NUCLED_WMI_USAGE_POWER_STATE || state->usage_type == NUCLED_WMI_USAGE_SOFTWARE) {
                state->blink_length = simple_strtol(arg, NULL, 10);
                if (state->blink_length < 1 || state->blink_length > 9) {
                    pr_warn("invalid argument for blink length\n");
                    return -EINVAL;
                }
            }
            break;
        case 5:
            // color (off or color name or #RRGGBB)
            if (state->color_type == NUCLED_WMI_TYPE_BLUE_AMBER) {
                if (!strcmp(arg, "off")) {
                    state->color[0] = NUCLED_WMI_COLOR_DISABLE;
                } else if (!strcmp(arg, "blue")) {
                    state->color[0] = NUCLED_WMI_COLOR_BLUE;
                } else if (!strcmp(arg, "amber")) {
                    state->color[0] = NUCLED_WMI_COLOR_AMBER;
                } else {
                    pr_warn("invalid argument for color\n");
                    return -EINVAL;
                }
            }
            break;
        default:
            // Too many args!
            return -EOVERFLOW;
        }

        // Track iterations
        i++;
    }
    return i == 6 ? 0: 1;
}

static ssize_t acpi_proc_write(struct file *filp, const char __user *buff,
    size_t len, loff_t *data)
{
    int ret = 0;
    char *input;
    int status;
    struct led_state state = {};

    // Move buffer from user space to kernel space
    input = vmalloc(len+1);
    if (!input) {
        return -ENOMEM;
    }

    if (copy_from_user(input, buff, len)) {
        return -EFAULT;
    }

    // Parse input string
    ret = parse_input(input, len, &state);

    vfree(input);

    if (ret == -EINVAL) {
        pr_warn("set_led_state: Invalid argument\n");
    } else if (ret == -EOVERFLOW) {
        pr_warn("set_led_state: Too many arguments\n");
    } else if (ret == 1) {
        pr_warn("set_led_state: Too few arguments\n");
    } else {
        status = nuc_led_set_state(&state);
        if (status) {
            pr_warn("set_led_state: WMI call failed\n");
        } else if (state.result_code != NUCLED_WMI_RETURN_SUCCESS) {
            pr_warn("set_led_state: WMI call returned error: (%02X)\n",
                state.result_code);
        }
    }

    return len;
}

static struct file_operations proc_acpi_operations = {
    .owner    = THIS_MODULE,
    .read     = acpi_proc_read,
    .write    = acpi_proc_write,
};

/* Init & unload */
static int __init init_nuc_led(void)
{
    struct proc_dir_entry *acpi_entry;
    kuid_t uid;
    kgid_t gid;

    // Make sure LED control WMI GUID exists
    if (!wmi_has_guid(NUCLED_WMI_MGMT_GUID)) {
        pr_warn("Intel NUC LED WMI GUID not found\n");
        return -ENODEV;
    }

    // Verify the user parameters
    uid = make_kuid(&init_user_ns, nuc_led_uid);
    gid = make_kgid(&init_user_ns, nuc_led_gid);

    if (!uid_valid(uid) || !gid_valid(gid)) {
        pr_warn("Intel NUC LED control driver got an invalid UID or GID\n");
        return -EINVAL;
    }

    // Create nuc_led ACPI proc entry
    acpi_entry = proc_create("nuc_led", nuc_led_perms, acpi_root_dir, &proc_acpi_operations);

    if (acpi_entry == NULL) {
        pr_warn("Intel NUC LED control driver could not create proc entry\n");
        return -ENOMEM;
    }

    proc_set_user(acpi_entry, uid, gid);

    pr_info("Intel NUC LED control driver loaded\n");

    return 0;
}

static void __exit unload_nuc_led(void)
{
    remove_proc_entry("nuc_led", acpi_root_dir);
    pr_info("Intel NUC LED control driver unloaded\n");
}

module_init(init_nuc_led);
module_exit(unload_nuc_led);
