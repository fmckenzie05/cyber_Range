#!/usr/bin/env python3
"""
Azure VM Credential Masking Script

Masks sensitive Azure VM credential values with custom rules for different fields.
Safe to commit the masked output to version control.

Usage:
    python mask_credentials.py

Input:  credential.txt (unmasked credentials - gitignored)
Output: credential_masked.txt (masked credentials - safe to commit)
"""

import re
import os
import sys


def mask_password(value):
    """Show only last 4 characters of password."""
    value = value.strip()
    if len(value) <= 4:
        return '*' * len(value)
    return '*' * (len(value) - 4) + value[-4:]


def mask_resource_group(value):
    """Show only first 2 characters of resource group."""
    value = value.strip()
    if len(value) <= 2:
        return value
    return value[:2] + '*' * (len(value) - 2)


def mask_subscription_id(value):
    """Replace subscription ID with just the word 'pacific'."""
    return "pacific"


def mask_ip_address(value):
    """Completely mask IP addresses."""
    value = value.strip()
    # Keep the format but mask the numbers
    if re.match(r'\d+\.\d+\.\d+\.\d+', value):
        return '***.***.***.***'
    return '*' * len(value)


def mask_virtual_network(value):
    """Keep 'Cyber' prefix, blur the rest."""
    value = value.strip()
    if value.startswith('Cyber'):
        # Find where 'Cyber' ends
        return 'Cyber' + '*' * (len(value) - 5)
    return value


def process_line(line, next_line_value=None):
    """
    Process a single line and apply appropriate masking rules.

    Args:
        line: Current line to process
        next_line_value: The value from the next line (for fields split across lines)

    Returns:
        Processed line with masking applied
    """
    # Skip comments and empty lines
    if line.strip().startswith('#') or not line.strip():
        return line

    # Handle "Password:" field
    if line.strip().startswith('Password:'):
        parts = line.split(':', 1)
        if len(parts) == 2:
            masked = mask_password(parts[1])
            return f"{parts[0]}: {masked}\n"

    # Handle fields where the value is on the next line
    # Resource group
    if line.strip() == 'Resource group':
        return line  # Return as-is, will handle the value line next

    # Check if this line is the value after "Resource group"
    if next_line_value == 'resource_group_value':
        if line.strip() and not line.strip().startswith(':') and not line.strip() == '(move)':
            # This is the actual resource group value
            masked = mask_resource_group(line.strip())
            return masked + '\n'

    # Subscription ID
    if line.strip() == 'Subscription ID':
        return line

    if next_line_value == 'subscription_id_value':
        if line.strip() and not line.strip().startswith(':'):
            return mask_subscription_id(line.strip()) + '\n'

    # Primary NIC public IP / Public IP address
    if 'Primary NIC public IP' in line or line.strip() == 'Public IP address':
        return line

    if next_line_value == 'public_ip_value':
        if re.match(r'\d+\.\d+\.\d+\.\d+', line.strip()):
            return mask_ip_address(line.strip()) + '\n'

    # Private IP address
    if line.strip() == 'Private IP address':
        return line

    if next_line_value == 'private_ip_value':
        if re.match(r'\d+\.\d+\.\d+\.\d+', line.strip()):
            return mask_ip_address(line.strip()) + '\n'

    # Virtual network/subnet
    if line.strip() == 'Virtual network/subnet':
        return line

    if next_line_value == 'vnet_value':
        if 'Cyber' in line:
            masked = mask_virtual_network(line.strip())
            return masked + '\n'

    return line


def mask_credentials(input_file='credential.txt', output_file='credential_masked.txt'):
    """
    Read credentials from input file and write masked version to output file.
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()

        masked_lines = []
        i = 0
        fields_masked = 0

        while i < len(lines):
            line = lines[i]
            next_line_context = None

            # Determine context for next line
            if 'Resource group' in line and i + 2 < len(lines):
                # Skip "(move)" and ":" lines, mask the actual value
                if i + 1 < len(lines) and lines[i + 1].strip() == '(move)':
                    masked_lines.append(line)
                    i += 1
                    masked_lines.append(lines[i])  # (move)
                    i += 1
                    if lines[i].strip() == ':':
                        masked_lines.append(lines[i])  # :
                        i += 1
                    # Next line is the resource group value
                    masked = mask_resource_group(lines[i].strip())
                    masked_lines.append(masked + '\n')
                    fields_masked += 1
                    i += 1
                    continue

            elif 'Subscription ID' in line:
                masked_lines.append(line)
                i += 1
                if i < len(lines) and lines[i].strip() == ':':
                    masked_lines.append(lines[i])
                    i += 1
                # Next line is subscription ID
                if i < len(lines):
                    masked_lines.append(mask_subscription_id(lines[i].strip()) + '\n')
                    fields_masked += 1
                    i += 1
                    continue

            elif 'Primary NIC public IP' in line or line.strip() == 'Public IP address':
                masked_lines.append(line)
                i += 1
                if i < len(lines) and lines[i].strip() == ':':
                    masked_lines.append(lines[i])
                    i += 1
                # Next line is IP
                if i < len(lines) and re.match(r'\d+\.\d+\.\d+\.\d+', lines[i].strip()):
                    masked_lines.append(mask_ip_address(lines[i].strip()) + '\n')
                    fields_masked += 1
                    i += 1
                    continue

            elif line.strip() == 'Private IP address':
                masked_lines.append(line)
                i += 1
                if i < len(lines) and lines[i].strip() == ':':
                    masked_lines.append(lines[i])
                    i += 1
                # Next line is private IP
                if i < len(lines) and re.match(r'\d+\.\d+\.\d+\.\d+', lines[i].strip()):
                    masked_lines.append(mask_ip_address(lines[i].strip()) + '\n')
                    fields_masked += 1
                    i += 1
                    continue

            elif line.strip() == 'Virtual network/subnet':
                masked_lines.append(line)
                i += 1
                if i < len(lines) and lines[i].strip() == ':':
                    masked_lines.append(lines[i])
                    i += 1
                # Next line has virtual network
                if i < len(lines) and 'Cyber' in lines[i]:
                    masked = mask_virtual_network(lines[i].strip())
                    masked_lines.append(masked + '\n')
                    fields_masked += 1
                    i += 1
                    continue

            # Process regular line
            processed = process_line(line)
            if processed != line and 'Password:' in line:
                fields_masked += 1
            masked_lines.append(processed)
            i += 1

        # Write output
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(masked_lines)

        print(f"[SUCCESS] Credential masking completed!")
        print(f"  Input:  {input_file}")
        print(f"  Output: {output_file}")
        print(f"  Fields masked: {fields_masked}")
        print(f"\nMasking rules applied:")
        print(f"  - Password: Last 4 characters visible")
        print(f"  - Resource Group: First 2 characters visible")
        print(f"  - Subscription ID: Replaced with 'pacific'")
        print(f"  - IP Addresses: Completely masked")
        print(f"  - Virtual Networks: 'Cyber' prefix kept, rest masked")
        print(f"\n'{output_file}' is safe to commit!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    mask_credentials()
