FROM tomcat:10.0.0-M4-jdk8-openjdk
ADD ./context.xml /usr/local/tomcat/conf/context.xml
# Web application
ADD web-app/uploading-migrated.war /usr/local/tomcat/webapps/ROOT.war
# Gadget lib
ADD ./groovy-2.3.9.jar /usr/local/tomcat/lib/groovy-2.3.9.jar
#ADD payload.sh /tmp/payload.sh

EXPOSE 8080
CMD ["/usr/local/tomcat/bin/catalina.sh", "run"]
