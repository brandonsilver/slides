#!/bin/sh
pandoc -t slidy --css styles.css --self-contained outline.md -o index.html
