#!/usr/bin/python2
# -*- coding: utf-8 -*-
#
# -- OpenStack Watchdog --
# A simple tool for cloud resource oversight.
#
# Cyrille TOULET <cyrille.toulet@univ-lille.fr>
# Mon  5 Nov 16:46:59 CET 2018


import ConfigParser
import smtplib
import string
import uuid
import datetime
import sys
import os
import ast
import keystoneauth1
import keystoneauth1.identity
import keystoneclient.v3.client
import mysql.connector


CONFIG_BASE = "/etc/openstack-watchdog/"
MAIN_CONFIG = "watchdog.conf"
PROJECT_DIR = "project.d/"

DEFAULT_CONF = {
    "auth_url": "https://controller:35357/v3",
    "admin_user": "admin",
    "admin_project": "admin",
    "admin_domain": "default",
    "admin_password": "************",
    "identity_api_version": "3",
    "image_api_version": "2",
    "compute_api_version": "2",
    "host": "controller",
    "user": "watchdog",
    "password": "************",
    "database": "nova",
    "smtp_host": "controller",
    "issuer_address": "no-reply@domain.org",
    "operator_address": "hpc@domain.org",
    "signature": "\n\n--\nWatchdog - OpenStack",
}

PROJECT_DEFAULT_CONF = {
    "domain": "",
    "project": "",
    "contacts": "[]",
    "whitelist": "[]",
    "allowed_subnets": "[]",
    "tcp_whitelist": "[]",
    "udp_whitelist": "[]",
    "stopped_alert_delay": "1",
    "running_alert_delay": "15",
    "orphan_alert_delay": "1",
    "inactive_alert_delay": "15",
}


class OpenstackWatchdog():
    """
    This class is used to run some oversight tests on OpenStack cloud.
    """

    def __init__(self, project_config):
        """
        Create connections to OpenStack cloud during class initialization
        :param project_config: (ConfigParser.ConfigParser) The project configuration
        """
        if not os.path.isfile(CONFIG_BASE + MAIN_CONFIG):
            print >> sys.stderr, "Configuration file " + MAIN_CONFIG + " not found."
            sys.exit(1)

        self.project_config = project_config
        self.config = ConfigParser.ConfigParser(DEFAULT_CONF)
        self.config.read(CONFIG_BASE + MAIN_CONFIG)

        credentials = dict()
        credentials['username'] = self.config.get('openstack', 'admin_user')
        credentials['password'] = self.config.get('openstack', 'admin_password')
        credentials['project_name'] = self.config.get('openstack', 'admin_project')
        credentials['project_domain_name'] = self.config.get('openstack', 'admin_domain')
        credentials['auth_url'] = self.config.get('openstack', 'auth_url')
        credentials['user_domain_name'] = self.config.get('openstack', 'admin_domain')

        self._id = str(uuid.uuid4())[-12:]

        try:
            auth = keystoneauth1.identity.v3.Password(**credentials)
            self.session = keystoneauth1.session.Session(auth=auth)
            self.keystone = keystoneclient.v3.client.Client(session=self.session)
        except:
            print >> sys.stderr, "Unable to connect API services to OpenStack"
            sys.exit(1)

        try:
            self.database = mysql.connector.connect(host=self.config.get('mysql', 'host'), 
                                                    user=self.config.get('mysql', 'user'), 
                                                    password=self.config.get('mysql', 'password'),
                                                    database=self.config.get('mysql', 'database'))
            self.mysql = self.database.cursor()
        except:
            print >> sys.stderr, "Unable to connect to MySQL database"
            sys.exit(1)


        self.domain = self.project_config.get('DEFAULT', 'domain')
        self.project = self.project_config.get('DEFAULT', 'project')
        self.contacts = ast.literal_eval(self.project_config.get('DEFAULT', 'contacts'))
        self.global_alerts = list()
        self.alerts = dict()


    def __del__(self):
        """
        Properly close connections before object deletion
        """
        if hasattr(self, "mysql"):
            self.mysql.close()

        if hasattr(self, "database"):
            self.database.close()



    def send_mail(self, dest, subject, message, enableCC = True):
        '''
        Send an email from HPC team

        :param dest: (str or list) The mail recipient(s) address
        :param subject: (str) The mail subject
        :param message: (str) The mail message
        :param enableCC: (bool) [optional] Add the CC addresses to recipient addresses
        :raise: HPCBackendException if an error occurs
        '''
        if type(dest) == list:
            to = dest
        else:
            to = [dest,]

        if enableCC:
            to.append(self.config.get('mail', 'operator_address'))

        headers = 'From: ' + self.config.get('mail', 'issuer_address') + '\n'
        headers += 'To: ' + ', '.join(to) + '\n'
        headers += 'Subject: ' + subject + '\n'
        headers += 'Content-Type: text/plain; charset=UTF-8\n\n'

        try:
            server = smtplib.SMTP(self.config.get('mail', 'smtp_host'))
            server.sendmail(self.config.get('mail', 'issuer_address'), to, 
                            headers.encode('utf-8') + message.encode('utf-8') + 
                            self.config.get('mail', 'signature').encode('utf-8'))
            server.quit()

        except Exception as error:
            print >> sys.stderr, str(error)



    def register_global_alert(self, message):
        """
        Register a global oversight alert
        :param message: (str) The alert to register
        """
        self.global_alerts.append(message)



    def register_alert(self, user_id, message):
        """
        Register an oversight alert
        :param user_id: (dict) The user ID
        :param message: (str) The alert to register
        """
        if not user_id in self.alerts:
            self.alerts[user_id] = list()

        self.alerts[user_id].append(message)



    def send_alerts(self):
        """
        Send registred alerts to project contact
        """
        users = self.get_users(self.domain, self.project)
        message = ""

        if len(self.global_alerts) > 0:
            message += "Global alerts:\n"
            for alert in self.global_alerts:
                message += " - " + alert + "\n"
            message += "\n"

        for uid in self.alerts:
            user = uid
            if uid in users:
                user = users[uid]["name"]
                if users[uid]["description"]:
                    user += " (" + users[uid]["description"] + ")"

            if len(self.alerts[uid]) > 1:
                message += "Alerts for " + user + ":\n"
            else:
                message += "Alert for " + user + ":\n"

            for alert in self.alerts[uid]:
                message += " - " + alert + "\n"

            message += "\n"

        subject = "[Cloud Watchdog] Alerts summary"
        project = self.get_project(self.project)
        if hasattr(project, "name"):
            subject += " for project " + project.name

        if len(self.global_alerts) + len(self.alerts) > 0:
            self.send_mail(self.contacts, subject, message)


    def get_project(self, project):
        """
        Get a keystone project from a project name or ID
        :param project: (str) The project name or ID
        :return: (keystone.projects.Project) The requested project
        """
        response = self.keystone.projects.get(project)
        return response



    def get_users(self, domain, project):
        """
        Get all users of a keystone project
        :param domain: (keystone.domains.Domain) The keystone domain
        :param project: (keystone.projects.Project) The keystone project
        :return: (list<keystone.users.User>) The users of specified domain
        """
        users = dict()

        for user in self.keystone.users.list(default_project=project, domain=domain):
            description = ""
            if hasattr(user, "description"):
                description = user.description
            users[user.id] = {"name": user.name, "description": description}

        return users



    def networks_oversight(self):
        """
        Oversight virtual networks and send report mail
        """
        self.mysql.execute('USE neutron;')
        self.mysql.execute('SELECT id, name FROM neutron.securitygroups WHERE project_id = "' + self.project + '";')
        rows = self.mysql.fetchall()

        security_groups = dict()
        for row in rows:
            (id, name) = row
            security_groups[id] = name

        allowed_subnets = ast.literal_eval(self.project_config.get('networks', 'allowed_subnets'))
        tcp_whitelist = ast.literal_eval(self.project_config.get('networks', 'tcp_whitelist'))
        udp_whitelist = ast.literal_eval(self.project_config.get('networks', 'udp_whitelist'))

        self.mysql.execute('SELECT id, security_group_id, ethertype, protocol, port_range_min, port_range_max, remote_ip_prefix FROM neutron.securitygrouprules WHERE protocol IS NOT NULL AND direction = "Ingress" AND project_id = "' + self.project + '";')
        rows = self.mysql.fetchall()

        for row in rows:
            (id, security_group_id, ethertype, protocol, port_range_min, port_range_max, remote_ip_prefix) = row
            subnet_mask = '/' + remote_ip_prefix.split('/')[-1]

            if (ethertype == "IPv4" and subnet_mask != "/32") or (ethertype == "IPv6" and subnet_mask != "/128"):
                if not remote_ip_prefix in allowed_subnets:
                    if port_range_min == port_range_max:
                        port = port_range_min
                    else:
                        port = str(min(port_range_min, port_range_max)) + ':' + str(max(port_range_min, port_range_max))

                    if (protocol == "tcp" and not port in tcp_whitelist) or (protocol == "udp" and not port in udp_whitelist):
                        message = ethertype + " " + protocol.upper() + " port " + str(port) + " open to " + remote_ip_prefix + " in security group " + security_groups[security_group_id] + " (" + security_group_id + ")"
                        self.register_global_alert(message)



    def instances_oversight(self):
        """
        Oversight server instances and send report mail
        """
        self.mysql.execute('USE nova;')
        self.mysql.execute('SELECT created_at, updated_at, deleted_at, deleted, uuid, user_id, project_id, vcpus, memory_mb, vm_state, display_name, node FROM instances WHERE deleted = "0" AND project_id = "' + self.project + '";')
        rows = self.mysql.fetchall()

        whitelist = ast.literal_eval(self.project_config.get('instances', 'whitelist'))
        now = datetime.date.today()

        for row in rows:
            (created_at, updated_at, deleted_at, deleted, uuid, user_id, project_id, vcpus, memory_mb, vm_state, display_name, node) = row

            if uuid in whitelist:
                continue

            created_delta = (now - created_at.date()).days
            updated_delta = (now - updated_at.date()).days

            if vm_state == "error":
                message = "Instance " + uuid
                if display_name:
                    message += " (" + display_name + ")"
                message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) in error ("
                message += vm_state.upper() + ") since " + str(updated_delta) + " days"
                self.register_alert(user_id, message)

            elif vm_state == "stopped":
                if updated_delta >= self.project_config.getint('instances', 'stopped_alert_delay'):
                    message = "Instance " + uuid
                    if display_name:
                        message += " (" + display_name + ")"
                    message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) stopped ("
                    message += vm_state.upper() + ") since " + str(updated_delta) + " days"
                    self.register_alert(user_id, message)

            elif vm_state == "active":
                if updated_delta >= self.project_config.getint('instances', 'running_alert_delay'):
                    message = "Instance " + uuid
                    if display_name:
                        message += " (" + display_name + ")"
                    message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) running ("
                    message += vm_state.upper() + ") since a long time (" + str(updated_delta) + " days)"
                    self.register_alert(user_id, message)



    def volumes_oversight(self):
        """
        Oversight server instances and send report mail
        """
        self.mysql.execute('USE cinder;')
        self.mysql.execute('SELECT created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name FROM volumes WHERE status != "deleted" AND project_id = "' + self.project + '";')
        rows = self.mysql.fetchall()

        whitelist = ast.literal_eval(self.project_config.get('volumes', 'whitelist'))
        now = datetime.date.today()

        for row in rows:
            (created_at, updated_at, deleted_at, deleted, id, user_id, project_id, size, status, display_name) = row

            if id in whitelist:
                continue

            created_delta = (now - created_at.date()).days
            updated_delta = (now - updated_at.date()).days

            if status in ['error', 'error_deleting']:
                message = "Volume " + id
                if display_name:
                    message += " (" + display_name + ")"
                message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) in error ("
                message += status.upper() + ") since " + str(updated_delta) + " days"
                self.register_alert(user_id, message)

            elif status == "available":
                if not display_name:
                    if updated_delta >= self.project_config.getint('volumes', 'orphan_alert_delay'):
                        message = "Volume " + id
                        message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) probably orphan ("
                        message += status.upper() + " since " + str(updated_delta) + " days)"
                        self.register_alert(user_id, message)

                else:
                    if updated_delta >= self.project_config.getint('volumes', 'inactive_alert_delay'):
                        message = "Volume " + id
                        if display_name:
                            message += " (" + display_name + ")"
                        message += " created on " + created_at.strftime("%d/%m/%Y") + " (" + str(created_delta) + " days ago) inactive ("
                        message += status.upper() + ") since " + str(updated_delta) + " days"
                        self.register_alert(user_id, message)



if __name__ == "__main__":
    projects = os.listdir(CONFIG_BASE + PROJECT_DIR)

    for project in projects:
        if project[-5:] == ".conf":
            project_config = ConfigParser.ConfigParser(PROJECT_DEFAULT_CONF)
            project_config.read(CONFIG_BASE + PROJECT_DIR + project)

            watchdog = OpenstackWatchdog(project_config)
            watchdog.networks_oversight()
            watchdog.instances_oversight()
            watchdog.volumes_oversight()
            watchdog.send_alerts()

    sys.exit(0)
