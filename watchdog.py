#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# -- OpenStack Cloud Watchdog --
# Watch for bad use of cloud, e.g. firewall critical rules and outdated virtual volumes.
#
# Cyrille TOULET <cyrille.toulet@univ-lille.fr>
# Wed 26 Sep 13:06:26 CEST 2018


import smtplib
import string
import uuid
import keystoneauth1
import keystoneauth1.identity
import keystoneclient.v3.client
import keystoneclient.v3.users
import keystoneclient.v3.domains
import neutronclient.v2_0.client
import novaclient.client
import mysql.connector
import datetime


# Cloud admin
DOMAIN = 'default'
PROJECT = 'admin'
LOGIN = 'admin'
PASSWORD = '****************'

# OpenStack
OS_AUTH_URL = "https://cloud.domain.org:35357/v3"
OS_IDENTITY_API_VERSION = 3
OS_IMAGE_API_VERSION = 2
OS_NOVA_API_VERSION = 2
OS_PROJECT_DOMAIN_NAME = DOMAIN
OS_USER_DOMAIN_NAME = DOMAIN
OS_USERNAME = LOGIN
OS_PASSWORD = PASSWORD
OS_PROJECT_NAME = PROJECT

# MySQL server
# Reminder - To create mysql user with limited privileges:
# CREATE USER 'watchdog'@'127.0.0.1' IDENTIFIED BY '****************';
# GRANT SELECT ON cinder.* TO 'watchdog'@'127.0.0.1';
# FLUSH PRIVILEGES;
MYSQL_HOST = '127.0.0.1'
MYSQL_USER = 'watchdog'
MYSQL_PASS = '****************'
MYSQL_DB = 'cinder'

# Mail server
MAIL_SMTP_HOST = 'localhost'
MAIL_ISSUER_ADDRESS = 'no-reply@domain.org'
MAIL_ADMIN_ADDRESS = 'cloud-admin@domain.org'
MAIL_CC_ADDRESSES = [MAIL_ADMIN_ADDRESS,]
MAIL_SIGNATURE = u'''\n\n--\n
Cloud Watchdog
'''

# Watchdog
PORTS_WHITELIST = [80, 443, 8080]
MONITORED_DOMAINS = ['default', ]
INACTIVE_GHOST_VOLUME_DELAY = 7
INACTIVE_VOLUME_DELAY = 45



class OpenstackWatchdog():
    """
    This class is used to run some survey tests on OpenStack cloud.
    """

    def __init__(self):
        """
        Create a connection to OpenStack Cloud during class initialization
        """
        credentials = dict()
        credentials['username'] = OS_USERNAME
        credentials['password'] = OS_PASSWORD
        credentials['auth_url'] = OS_AUTH_URL
        credentials['project_name'] = OS_PROJECT_NAME
        credentials['project_domain_name'] = OS_PROJECT_DOMAIN_NAME
        credentials['user_domain_name'] = OS_USER_DOMAIN_NAME

        self._id = str(uuid.uuid4())[-12:]

        try:
            auth = keystoneauth1.identity.v3.Password(**credentials)
            self.session = keystoneauth1.session.Session(auth=auth)
            self.keystone = keystoneclient.v3.client.Client(session=self.session)
            self.neutron = neutronclient.v2_0.client.Client(session=self.session)
            self.nova = novaclient.client.Client(OS_NOVA_API_VERSION , session=self.session)
        except:
            print "Unable to connect API services to OpenStack"

        try:
            self.database = mysql.connector.connect(host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASS, database=MYSQL_DB)
            self.mysql = self.database.cursor()
        except:
            print "Unable to connect to MySQL database"



    def __del__(self):
        """
        Properly close connections before object deletion
        """
        self.mysql.close()
        self.database.close()



    def sendMail(self, dest, subject, message, enableCC = True):
        '''
        Send an email from HPC team

        :param dest: (str) The mail recipient address
        :param subject: (str) The mail subject
        :param message: (str) The mail message
        :param enableCC: (bool) [optional] Add the CC addresses to recipient addresses
        :raise: HPCBackendException if an error occurs
        '''

        to = [dest,]
        if enableCC:
            to = [dest,] + MAIL_CC_ADDRESSES

        headers = 'From: ' + MAIL_ISSUER_ADDRESS + '\n'
        headers += 'To: ' + ', '.join(to) + '\n'
        headers += 'Subject: ' + subject + '\n'
        headers += 'Content-Type: text/plain; charset=UTF-8\n\n'

        try:
            server = smtplib.SMTP(MAIL_SMTP_HOST)
            server.sendmail(MAIL_ISSUER_ADDRESS, to, headers.encode('utf-8') + message.encode('utf-8') + MAIL_SIGNATURE.encode('utf-8'))
            server.quit()

        except Exception as error:
            print(str(error))



    def _get_project(self, project_id):
        """
        Get a keystone project from a project ID
        :param project_id: (str) The project ID
        :return: (keystone.projects.Project) The requested project
        """
        response = self.keystone.projects.get(project_id)

        return response



    def _get_security_groups(self):
        """
        Get all security groups
        :return: (list) The security groups
        """
        response = self.neutron.list_security_groups()

        return response['security_groups']



    def _get_security_group_rules(self, security_group_id):
        """
        Get all rules of a security group
        :param security_group_id: (str) The id of security group
        :return: (list) The rules of security group
        :raises Exception: An error occurs during rules fetching
        """
        response = self.neutron.list_security_group_rules(security_group_id=security_group_id)

        return response['security_group_rules']



    def _get_monitored_domains(self):
        """
        Get the list of monitored projects
        :return: (list<keystone.domains.Domain>) The monitored projects
        """
        domains = self.keystone.domains.list()
        monitored_domains = list()
        for domain in domains:
            if domain.name in MONITORED_DOMAINS:
                monitored_domains.append(domain)

        return monitored_domains



    def _get_users(self, user_domain):
        """
        Get all users of a keystone project
        :param user_domain: (keystone.domains.Domain) The keystone domain
        :return: (list<keystone.users.User>) The users of specified domain
        """
        users = dict()
        for user in self.keystone.users.list(domain=user_domain):
            description = ''
            if user.description:
                description = user.description
            users[user.id] = {'name': user.name, 'description': description}

        return users



    def watch_security_groups_ports(self):
        """
        Survey security groups ports and send report mail
        """
        alerts = False
        first = True
        security_groups = self._get_security_groups()
        subject = u'[Cloud Watchdog] Alerte de sécurité - Ouverture de ports'
        message = u''

        for security_group in security_groups:
            new_security_group = True
            group_id = security_group['id']
            name = security_group['name']
            project_id = security_group['project_id']
            rules = self._get_security_group_rules(group_id)

            for rule in rules:
                rule_id = rule['id']
                protocol = rule['protocol']
                ip = rule['remote_ip_prefix']
                port_range_min = rule['port_range_min']
                port_range_max = rule['port_range_max']

                if (protocol == 'tcp' or protocol == 'udp') \
                   and ip == '0.0.0.0/0' \
                   and port_range_min == port_range_max  \
                   and not (port_range_min in PORTS_WHITELIST):
                    if new_security_group:
                        new_security_group = False
                        alerts = True

                        project = self._get_project(project_id)
                        project_name = project.name
                        project_description = project.description

                        if not(first):
                            message += u'\n\n'
                            print

                        first = False


                        message += u'Alerte(s) pour le groupe de sécurité ' + name + u' (' + group_id + u')\n'
                        message += u'Projet ' + project_name + u' (' + project_id + u')\n'

                    message += u' - Règle en alerte sur le port ' + protocol.upper() + ' ' + str(port_range_min) + u' (' + rule_id + u')\n'

        if alerts:
            self.sendMail(MAIL_ADMIN_ADDRESS, subject, message, False)



    def watch_default_security_groups(self):
        """
        Survey default security groups and send report mail
        """
        alerts = False
        first = True
        security_groups = self._get_security_groups()
        subject = u'[Cloud Watchdog] Alerte de sécurité - Présence de règles dans des groupes de sécurité par défaut'
        message = u''

        for security_group in security_groups:
            new_security_group = True
            group_id = security_group['id']
            name = security_group['name']
            project_id = security_group['project_id']
            rules = self._get_security_group_rules(group_id)

            if name == 'default':
                for rule in rules:
                    rule_id = rule['id']
                    protocol = rule['protocol']
                    ip = rule['remote_ip_prefix']
                    port_range_min = rule['port_range_min']
                    port_range_max = rule['port_range_max']

                    if (protocol == 'tcp' or protocol == 'udp'):
                        if new_security_group:
                            new_security_group = False
                            alerts = True

                            project = self._get_project(project_id)
                            project_name = project.name
                            project_description = project.description

                            if not(first):
                                message += u'\n\n'
                                print

                            first = False

                            message += u'Alerte(s) pour le groupe de sécurité ' + name + u' (' + group_id + u')\n'
                            message += u'Projet ' + project_name + u' (' + project_id + u')\n'

                        message += u' - Ports ' + protocol.upper() + ' ' + str(port_range_min) + u':' + str(port_range_max) + u' pour le ' + ip + u' (' + rule_id + u')\n'

        if alerts:
            self.sendMail(MAIL_ADMIN_ADDRESS, subject, message, False)



    def watch_volumes_in_error(self):
        """
        Survey virtual volumes in error status and send report mail
        """
        subject = u'[Cloud Watchdog] Volumes en erreur détectés'
        message = u''


        monitored_domains = self._get_monitored_domains()
        users = dict()

        for monitored_domain in monitored_domains:
            domain_users = self._get_users(monitored_domain)
            users.update(domain_users)

        self.mysql.execute('SELECT created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name FROM volumes WHERE status != "deleted";')
        rows = self.mysql.fetchall()

        stats = dict()
        now = datetime.date.today()

        for row in rows:
            (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = row

            if not user_id in stats:
                stats[user_id] = list()

            stats[user_id].append(row)

        volumes_in_error = dict()

        for uid in stats:
            user = uid
            if uid in users:
                user = users[uid]['name']
                if users[uid]['description']:
                    user = users[uid]['name'] + ' (' + users[uid]['description'] + ')'

            for volume in stats[uid]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                if status in ['error', 'error_deleting']:
                    if not user in volumes_in_error:
                        volumes_in_error[user] = list()
                    volumes_in_error[user].append(volume)

        for user in volumes_in_error:
            if len(message) > 0:
                message += '\n\n'

            message += u'Volume(s) en erreur appartenant(s) à ' + user + ' :\n'
        
            for volume in volumes_in_error[user]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                created_delta = (now - created_at.date()).days
                updated_delta = (now - updated_at.date()).days
                message += ' - Volume ' + id
                if display_name:
                    message += ' (' + display_name + ')'
                message += u' créé le ' + created_at.strftime("%d/%m/%Y") + ' (il y a ' + str(created_delta) + ' jours) en erreur (' + status.upper() + ') depuis ' + str(updated_delta) + ' jours\n'

        if len(message) > 0:
            self.sendMail(MAIL_ADMIN_ADDRESS, subject, message, False)



    def watch_volumes_inactive(self):
        """
        Survey inactive virtual volumes and send report mail
        """
        subject = u'[Cloud Watchdog] Volumes inactifs détectés'
        message = u''


        monitored_domains = self._get_monitored_domains()
        users = dict()

        for monitored_domain in monitored_domains:
            domain_users = self._get_users(monitored_domain)
            users.update(domain_users)

        self.mysql.execute('SELECT created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name FROM volumes WHERE status != "deleted";')
        rows = self.mysql.fetchall()

        stats = dict()
        now = datetime.date.today()

        for row in rows:
            (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = row

            if not user_id in stats:
                stats[user_id] = list()

            stats[user_id].append(row)

        volumes_inactive = dict()

        for uid in stats:
            user = uid
            if uid in users:
                user = users[uid]['name']
                if users[uid]['description']:
                    user = users[uid]['name'] + ' (' + users[uid]['description'] + ')'

            for volume in stats[uid]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                if status == 'available':
                    updated_delta = (now - updated_at.date()).days

                    if display_name:
                        if updated_delta >= INACTIVE_VOLUME_DELAY:
                            if not user in volumes_inactive:
                                volumes_inactive[user] = list()
                            volumes_inactive[user].append(volume)

        for user in volumes_inactive:
            if len(message) > 0:
                message += '\n\n'

            message += u'Volume(s) inactif(s) appartenant(s) à ' + user + ' :\n'
        
            for volume in volumes_inactive[user]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                created_delta = (now - created_at.date()).days
                updated_delta = (now - updated_at.date()).days
                message += ' - Volume ' + id
                if display_name:
                    message += ' (' + display_name + ')'
                message += u' créé le ' + created_at.strftime("%d/%m/%Y") + ' (il y a ' + str(created_delta) + ' jours) inactif (' + status.upper() + ') depuis ' + str(updated_delta) + ' jours\n'

        if len(message) > 0:
            self.sendMail(MAIL_ADMIN_ADDRESS, subject, message, False)



    def watch_ghost_volumes(self):
        """
        Survey outdated virtual volumes and send report mail
        """
        subject = u'[Cloud Watchdog] Volumes fantômes détectés'
        message = u''


        monitored_domains = self._get_monitored_domains()
        users = dict()

        for monitored_domain in monitored_domains:
            domain_users = self._get_users(monitored_domain)
            users.update(domain_users)

        self.mysql.execute('SELECT created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name FROM volumes WHERE status != "deleted";')
        rows = self.mysql.fetchall()

        stats = dict()
        now = datetime.date.today()

        for row in rows:
            (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = row

            if not user_id in stats:
                stats[user_id] = list()

            stats[user_id].append(row)

        ghost_volumes = dict()

        for uid in stats:
            user = uid
            if uid in users:
                user = users[uid]['name']
                if users[uid]['description']:
                    user = users[uid]['name'] + ' (' + users[uid]['description'] + ')'

            for volume in stats[uid]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                if status == 'available':
                    updated_delta = (now - updated_at.date()).days

                    if not display_name:
                        if updated_delta >= INACTIVE_GHOST_VOLUME_DELAY:
                            if not user in ghost_volumes:
                                ghost_volumes[user] = list()
                            ghost_volumes[user].append(volume)

        for user in ghost_volumes:
            if len(message) > 0:
                message += '\n\n'

            message += u'Volume(s) fantôme(s) appartenant(s) à ' + user + ' :\n'
        
            for volume in ghost_volumes[user]:
                (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = volume

                created_delta = (now - created_at.date()).days
                updated_delta = (now - updated_at.date()).days
                message += ' - Volume ' + id
                if display_name:
                    message += ' (' + display_name + ')'
                message += u' créé le ' + created_at.strftime("%d/%m/%Y") + ' (il y a ' + str(created_delta) + ' jours) inactif (' + status.upper() + ') depuis ' + str(updated_delta) + ' jours\n'

        if len(message) > 0:
            self.sendMail(MAIL_ADMIN_ADDRESS, subject, message, False)



if __name__ == "__main__":
    watchdog = OpenstackWatchdog()
    watchdog.watch_security_groups_ports()
    watchdog.watch_default_security_groups()
    watchdog.watch_volumes_in_error()
    watchdog.watch_volumes_inactive()
    watchdog.watch_ghost_volumes()
