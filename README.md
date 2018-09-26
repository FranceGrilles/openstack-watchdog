# OpenStack Watchdog

A simple "watchdog" script to check the use of OpenStack cloud and ensure compliance with best practices.


## Installation

Clone the project repository on your controller node and place a copy of script in a place of your choice:
```bash
git clone https://github.com/FranceGrilles/openstack-watchdog.git /opt/openstack-watchdog-src
cp /opt/openstack-watchdog-src/watchdog.py /root/watchdog.py
chmod 700 /root/watchdog.py
```

Generate a suitable password and create a read-only user for cinder database:
```bash
WATCHDOG_PASS=$(openssl rand -base64 21)
mysql -u root -p -e "CREATE USER 'watchdog'@'127.0.0.1' IDENTIFIED BY '${WATCHDOG_PASS}';"
mysql -u root -p -e "GRANT SELECT ON cinder.* TO 'watchdog'@'127.0.0.1';"
mysql -u root -p -e "FLUSH PRIVILEGES;"
echo "Generated password: ${WATCHDOG_PASS}"
```


## Configuration

Edit **/root/watchdog.py** and configure the following values:
 * **DOMAIN:** The domain of your cloud admin user
 * **PROJECT:** The admin project
 * **LOGIN:** The admin user
 * **PASSWORD:** The password of admin user
 * **OS_AUTH_URL:** The keystone endpoint
 * **MYSQL_PASS:** The password of 'watchdog' mysql user
 * **MAIL_ISSUER_ADDRESS:** The mail address of reports issuer
 * **MAIL_ADMIN_ADDRESS:** The mail of the cloud admin team
 * **PORTS_WHITELIST:** The TCP/UDP ports allowed on Internet
 * **MONITORED_DOMAINS:** The keystone domains to monitor
 * **INACTIVE_GHOST_VOLUME_DELAY:** The number of days before consider a detached unamed volume as ghost
 * **INACTIVE_VOLUME_DELAY:** The number of days before consider a detached volume as inactive

Once the configuration ready, manually test the script execution:
```bash
/root/watchdog.py
```
You may receive report emails.

If no error occurs, add a daily execution in your crontab, like:
```
  30 7  *  *  * root    /usr/bin/python2 /root/watchdog.py
```
