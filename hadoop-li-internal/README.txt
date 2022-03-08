Hadoop LinkedIn Internal Dependencies Project
---------------------------------------------

This module allows adding dependencies from LI Artifactory so that they will be
included in the distribution package under share/hadoop/common/lib.

Note: In order for the Maven build to be able to consume artifacts from
Artifactory, the artifacts must be published alongside a POM file.
See https://iwww.corp.linkedin.com/wiki/cf/x/ZgpnE for instructions on how to
publish a POM file to Artifactory from an MP/Gradle project.
