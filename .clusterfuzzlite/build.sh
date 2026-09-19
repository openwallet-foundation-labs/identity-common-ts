#!/bin/bash -eu

# Install pnpm and build project packages
npm install -g pnpm@10.28.0
pnpm install --frozen-lockfile
pnpm build
pnpm build:fuzz

# Compile Jazzer.js fuzz targets into $OUT
compile_javascript_fuzzer identity-common-ts dist-fuzz/sd-jwt.fuzz.mjs fuzzer_sd_jwt
compile_javascript_fuzzer identity-common-ts dist-fuzz/cbor.fuzz.mjs fuzzer_cbor --sync
compile_javascript_fuzzer identity-common-ts dist-fuzz/dcql.fuzz.mjs fuzzer_dcql --sync
