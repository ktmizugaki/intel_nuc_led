# Intel NUC7CJYH LED Control

This is a simple kernel module to partially control the power LED on Intel NUC7CJYH.

This module is intended as a proof-of-concept and will not be maintained further.
Use this on your own responsibility.


## Requirements

Requirements:

* Intel NUC7CJYH
* BIOS JY0045
* ACPI/WMI support in kernel

## Building

THe `nuc_led` kernel module supports building and installing "from source" directly or using `dkms`.

### Installing Build Dependencies

Ubuntu:

```
apt-get install build-essential linux-headers-$(uname -r)

# DKMS dependencies
apt-get install debhelper dkms
```

Redhat:

```
yum groupinstall "Development Tools"
yum install kernel-devel-$(uname -r)

# Install appropriate EPEL for DKMS if needed by your RHEL variant
yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

yum install dkms
```

### Building and Installing "from source"

```
make clean
make install
```

### Building and Installing Using DKMS

Build and install without system packaging:

```
make dkms-install
```

Uninstall without system packaging:

```
make dkms-uninstall
```

Build and install using system packaging:

```
# Ubuntu
make dkms-deb

# RHEL
make dkms-rpm

# Install generated DEB/RPM from the folder specified in the output using system package manager
```

## Usage
    
This driver works via '/proc/acpi/nuc_led'.  To get current LED state:

```
cat /proc/acpi/nuc_led
```
    
To change the LED state:

```
 echo '<led>,<usage type>,<brightness>,<blink>,<blink speed>,<color>' | sudo tee /proc/acpi/nuc_led > /dev/null
```

|LED  |Description                         |
|-----|------------------------------------|
|power|The power button LED.               |
|hdd  |HDD indicator LED. not controllable.|
|ring |N/A                                 |

|Usage Type|Description                    |
|----------|-------------------------------|
|power     |power indicator                |
|hdd       |HDD activity indicator LED. N/A|
|sw        |Software control. N/A          |
|disable   |Disable LED. N/A               |

Brightness:

* any integer between `0` and `100`.

|Blink Option|Description      |
|------------|-----------------|
|solid       |always on        |
|breathing   |fade out/in      |
|pulsing     |fade out, then on|

Blink Speed:

*integer from `1` (fastest) to `9` (slowest).

|LED Color|power|
|---------|:---:|
|off      |X    |
|amber    |X    |
|blue     |X    |
|cyan     |     |
|green    |     |
|pink     |     |
|red      |     |
|white    |     |
|yellow   |     |
    
Example execution to cause the power LED blink orange at a medium rate at partial intensity:

    echo 'power,power,80,breathing,amber' | sudo tee /proc/acpi/nuc_led > /dev/null

Errors in passing parameters will appear as warnings in dmesg.

Note: SW control mode does not work. Only setting power LED to power indicator is possible because of WMI.
Luckily, since setting power indicator option for power LED seems to work, you can control the LED at some extent.
Although setting HDD LED can be set to hdd indicator, setting indicator options didn't work and
it is no fun, so setting hdd led isn't included.

You can change the owner, group and permissions of `/proc/acpi/nuc_led` by passing parameters to the nuc_led kernel module. Use:

* `nuc_led_uid` to set the owner (default is 0, root)
* `nuc_led_gid` to set the owning group (default is 0, root)
* `nuc_led_perms` to set the file permissions (default is r+w for group and user and r for others)
