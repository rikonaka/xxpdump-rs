#!/bin/bash

BINARY_NAME="xxpdump"
OUTPUT_DIR="./target"
BUILD_DIR="./target"

mkdir -p "$OUTPUT_DIR"

TARGETS=$(find "$BUILD_DIR" -maxdepth 1 -type d -name "*unknown*" -printf "%f\n")

if [ -z "$TARGETS" ]; then
    echo "Error: no compiled target architecture found"
    exit 1
fi

echo "Found the following target architecture: $TARGETS"
echo "Start packaging..."

for TARGET in $TARGETS; do
    BINARY_PATH="$BUILD_DIR/$TARGET/release/$BINARY_NAME"
    
    if [ ! -f "$BINARY_PATH" ]; then
        echo "Release version not found, trying debug version..."
        BINARY_PATH="$BUILD_DIR/$TARGET/debug/$BINARY_NAME"
    fi
    
    if [ ! -f "$BINARY_PATH" ]; then
        echo "Warning: executable not found in $TARGET, skipping target architecture..."
        continue
    fi
    
    TEMP_DIR=$(mktemp -d)
    mkdir -p "$TEMP_DIR"
    
    cp "$BINARY_PATH" "$TEMP_DIR/"
    
    # for FILE in README* LICENSE*; do
    #     if [ -f "$FILE" ]; then
    #         cp "$FILE" "$TEMP_DIR/$BINARY_NAME-$TARGET/"
    #     fi
    # done

    ARCHIVE_NAME="$OUTPUT_DIR/$BINARY_NAME-$TARGET.tar.gz"
    tar -czf "$ARCHIVE_NAME" -C "$TEMP_DIR" "$BINARY_NAME"
    
    rm -rf "$TEMP_DIR"
    
    echo "The compressed package has been created: $ARCHIVE_NAME"
done

echo "Packaging is complete, all files have been saved to: $OUTPUT_DIR"
