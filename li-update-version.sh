#!/usr/bin/env bash
set -xe

base_version=3.3

patch_count=`git log --oneline li-${base_version}-base..HEAD | wc -l | tr -d '[[:space:]]'`

echo "Found ${patch_count} patches applied to base"

li_version="${base_version}.${patch_count}"

echo "New version: ${li_version}"

echo "Updating version info..."
mvn versions:set -DnewVersion=${li_version} -DgenerateBackupPoms=false
mvn versions:set-property -Dproperty=hadoop.version -DnewVersion=${li_version}

# Note: this is for building the artifact-spec in the li-hadoop multiproduct
echo "Creating build.properties file with new version info..."
cat > build.properties <<EOF
version=${li_version}
EOF

echo "Done!"


