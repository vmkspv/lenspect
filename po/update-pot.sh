#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;94m'
GRAY='\033[0;37m'
NC='\033[0m'

print_step() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_info() { echo -e "${GRAY}[i]${NC} $1"; }

cd "$(dirname "$0")/.."

print_step "Updating POTFILES..."
{
    find data -type f \( -name "*.desktop.in" -o -name "*.metainfo.xml.in" \) ! -name "*.SearchProvider.desktop.in"
    find src -type f -name "*.py" -print0 | xargs -0 grep -l -E "(_\(['\"]|N_\(['\"]|C_\(['\"])"
    find src -type f -name "*.blp"
} | sort > po/POTFILES
print_success "POTFILES updated successfully."

print_step "Extracting translatable strings..."
xgettext --files-from=po/POTFILES \
         --from-code=UTF-8 \
         --output=po/lenspect.pot \
         --package-name=lenspect \
         --copyright-holder="Vladimir Kosolapov" \
         --msgid-bugs-address="https://github.com/vmkspv/lenspect/issues" \
         --add-comments=Translators \
         --keyword=_ \
         --keyword=C_:1c,2 \
         --keyword=N_ \
         --keyword=Q_ \
         2>/dev/null

print_step "Updating POT creation date..."
sed -i 's/^"POT-Creation-Date:.*/"POT-Creation-Date: '"$(date +'%Y-%m-%d %H:%M%z')"'\\n"/' po/lenspect.pot

print_success "lenspect.pot updated successfully."
print_info "Total translatable strings: $(grep -c msgid po/lenspect.pot)"
