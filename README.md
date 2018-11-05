# OpenStack Watchdog

A simple "watchdog" script to check the use of OpenStack cloud and ensure compliance with best practices.


## Requirements

The watchdog script requires access to specific OpenStack databases.

To generate a suitable password and create a read-only user:
```bash
WATCHDOG_PASS=$(openssl rand -base64 21)
mysql -u root -p -e "CREATE USER 'watchdog'@'127.0.0.1' IDENTIFIED BY '${WATCHDOG_PASS}';"
mysql -u root -p -e "GRANT SELECT ON neutron.* TO 'watchdog'@'127.0.0.1';"
mysql -u root -p -e "GRANT SELECT ON nova.* TO 'watchdog'@'127.0.0.1';"
mysql -u root -p -e "GRANT SELECT ON cinder.* TO 'watchdog'@'127.0.0.1';"
mysql -u root -p -e "FLUSH PRIVILEGES;"
echo "Generated password: ${WATCHDOG_PASS}"
```


## Installation

Clone the project repository on your controller node:
```bash
git clone https://github.com/FranceGrilles/openstack-watchdog.git /opt/openstack-watchdog-src
```

Place the watchdog script in a place of your choice:
```bash
cp /opt/openstack-watchdog-src/watchdog.py /root/watchdog.py
chmod 700 /root/watchdog.py
```

Create the base configuration:
```bash
mkdir -p /etc/openstack-watchdog/project.d/
cp /opt/openstack-watchdog-src/watchdog.conf /etc/openstack-watchdog/
chmod -R 700 /etc/openstack-watchdog/
```


## Configuration

Configure the global settings in **/etc/openstack-watchdog/watchdog.conf**.

To monitor an OpenStack project, create a specific configuration file. For example, for project **proj1**:
```
cp /opt/openstack-watchdog-src/sample.conf /etc/openstack-watchdog/project.d/proj1.conf
```

The minimal configuration for a project is:
 * **DEFAULT.domain**: The domain ID
 * **DEFAULT.project**: The project ID
 * **DEFAULT.contacts**: The project contacts


Once the configuration ready, manually test the script execution:
```bash
/root/watchdog.py
```
You may receive report emails.

If no error occurs, add a daily execution in your crontab, like:
```
  30 7  *  *  * root    /usr/bin/python2 /root/watchdog.py
```
