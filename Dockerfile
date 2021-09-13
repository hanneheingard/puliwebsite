FROM openjdk:11
EXPOSE 8081
ADD /build/libs/puli-0.0.1-SNAPSHOT.war puli.main.war
CMD jar -xvf puli.main.war ; cd WEB-INF ; java -classpath "lib/*:classes/." puli.PuliApplication