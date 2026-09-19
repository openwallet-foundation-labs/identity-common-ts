FROM gcr.io/oss-fuzz-base/base-builder-javascript

COPY . $SRC/identity-common-ts
WORKDIR $SRC/identity-common-ts
COPY .clusterfuzzlite/build.sh $SRC/
