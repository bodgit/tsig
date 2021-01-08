FROM centos/systemd:latest as kdc

EXPOSE 88
EXPOSE 464

STOPSIGNAL SIGRTMIN+3

RUN yum install -y krb5-workstation && yum update -y && yum clean all
COPY --chown=root:root krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

RUN yum install -y krb5-server && yum clean all
COPY --chown=root:root kdc.conf /var/kerberos/krb5kdc/kdc.conf
COPY --chown=root:root kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
RUN chmod 600 /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl

RUN systemctl enable krb5kdc.service kadmin.service

RUN kdb5_util create -s -r EXAMPLE.COM -P $(echo ${RANDOM}${RANDOM}${RANDOM} | md5sum | cut -d ' ' -f 1)

RUN kadmin.local addprinc -pw password test
RUN kadmin.local ktadd -norandkey -k /etc/test.keytab test
RUN kadmin.local addprinc -randkey DNS/ns.example.com
RUN kadmin.local ktadd -k /etc/named.keytab DNS/ns.example.com

FROM centos/systemd:latest as ns

EXPOSE 53

STOPSIGNAL SIGRTMIN+3

RUN yum install -y krb5-workstation && yum update -y && yum clean all
COPY --chown=root:root krb5.conf /etc/krb5.conf
RUN chmod 644 /etc/krb5.conf

RUN yum install -y bind bind-utils && yum clean all
COPY --from=kdc --chown=root:named /etc/named.keytab /etc/named.keytab
RUN chmod 640 /etc/named.keytab

RUN systemctl enable named.service

COPY --chown=root:named named.conf /etc/named.conf
RUN chmod 640 /etc/named.conf
COPY --chown=named:named db.* /var/named/dynamic/
RUN chmod 644 /var/named/dynamic/db.*

FROM scratch as keytab
COPY --from=kdc /etc/test.keytab /test.keytab
