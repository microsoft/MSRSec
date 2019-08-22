# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
from __future__ import print_function

import os, sys, json, codecs

# Reads a utf-8 encoded json file containing default variables, then generates 
# a .c file which is responsible for placing those variables into memory when
# the TA first runs (ie has no stored NV state available).
# ex: python defaultvars.py input.json output.c

# The json file must be utf-8 encoded.
# -- The name field may contain valid unicode characters so long as they can be encoded
#       with ECS2 (a subset of utf-16 which does not allow 4 byte merged characters).
# -- The binary path is relative to the TA root (AuthvVars/), or
#       absolute (/path/to/file.json).
# -- The guid can be either valid C GUID struct syntax or one of the well known 
#       GUIDs from uefidefs.h
# -- The attributes are also selected from uefidefs.h.
# 
# Example JSON to add a one-time volatile variable:
# {
#     "variables": [
#         {
#             "name": "ECS2 Variable Name",
#             "bin_path": "/path/to/variable.bin",
#             "guid": "{0xe4b297c1, 0x507d, 0x407f, {0xbe,0x4a,0xe9,0x25,0x68,0x69,0x25,0x14}}",
#                                               < OR >
#             "guid": "<EFI_IMAGE_SECURITY_DATABASE_GUID / EFI_GLOBAL_VARIABLE>",
#             "attributes": "EFI_VARIABLE_APPEND_WRITE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS"
#         }
#     ]
# }

def write_header(f, input_file_name):
    f.write(
'''
/* Automatically generated file created by defaultvars.py */
/* Add hard-coded variables to the image by editing %s */

#include <defaultvars.h>

''' % input_file_name)

# Convert characters to a valid ECS2 encoding. Leave a subset of basic ASCII
#  characters alone, but convert anything else to the form \x1234. Each 
# character of the form \x1234 is enclosed in quotes: ie "foo / bar" becomes 
# L"foo " "\x002f" " bar". The compiler will automatically  concatenate the 
# strings. Throws an error on any valid utf-16 characters which cannot be
# represented by ECS2.
def convert_to_ecs2_wchar(char):
    if ord(char) >= 0xd800 and ord(char) <= 0xdfff:
        raise ValueError("Invalid ECS2 encoding (UTF-16 surrogate) for character '%c'" % char)
    if ord(char) > 0xffff:
        raise ValueError("Invalid ECS2 encoding for character '%c', to large for ECS2" % char)
    if ((ord(char) in range(ord('a'), ord('z'))) or
            (ord(char) in range(ord('A'), ord('Z'))) or
            (ord(char) in range(ord('0'), ord('9'))) or
            (ord(char) == ord(' '))):
        # Leave very basic characters alone (a-z,A-Z,0-9,' ')
        return char
    else:
        # Generates something of the form: " "\x0123" " for everything else
        return (r'" "\x' + ('%04x' % ord(char)) + '" "' )

# We could compile unicode strings here, but it is easier to convert to hex 
# representation instead of handing escaping everything correctly. Also 
# verify we are not encoding any 4 byte characters which ECS2 can't handle.
def format_wchar_string(string):
    return 'L"' + ''.join(convert_to_ecs2_wchar(c) for c in string) + '"'

# Formats data into a valid C array (ie { 0x0, 0x1, 0x2, ...})
def format_byte_array(bytes):
    line_length = 16
    return '{\n\t%s\n}' % (''.join([
        '0x%02x, ' % byte + ('\n\t' if ((i+1) % line_length == 0) else '') 
            for i, byte in enumerate(bytearray(bytes))
        ]))

# Generate tupples of the form:
#   (name, <binary data>, guid, attributes)
# from a file containing json data.
def parse_json(json_file):
    json_data = json_file.read()
    json_data = json.loads(json_data, encoding='utf-8')
    vars = list()
    for variable in json_data['variables']:
        variable_name = variable['name']
        variable_bin_path = variable['bin_path']
        variable_guild = variable['guid']
        variable_attributes = variable['attributes']

        with open(variable_bin_path, 'rb') as bin_file:
            vars.append((format_wchar_string(variable_name),
                    format_byte_array(bin_file.read()),
                    variable_guild,
                    variable_attributes))
    return vars

# Generates a code chunk for each variable of the form:
#       WCHAR var_<VAR_NUM>_name[] = L"Abcd" "\x1234" "5678";
#       GUID var_<VAR_NUM>_guid = {0x12345678,0x9abc,0xdef0,{0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}};
#               <or>
#       GUID var_<VAR_NUM>_guid = <EFI_IMAGE_SECURITY_DATABASE_GUID / EFI_GLOBAL_VARIABLE>
#       ATTRIBUTES var_<VAR_NUM>_attributes = "ATTR1 | ATTR2 | ... ";
#       BYTE var_<VAR_NUM>_bin[] = { 0x0, 0x1, 0x2, ... };
def write_variables(f, variables):
    for i,var in enumerate(variables):
        f.write(('WCHAR var_%d_name[] = ' % i) + var[0] + ";\n")
        f.write(('GUID var_%d_guid = ' % i) + var[2] + ";\n")
        f.write(('ATTRIBUTES var_%d_attributes = {' % i) + var[3] + "};\n")
        f.write(('BYTE var_%d_bin[] = ' % i) + var[1] + ";\n")
        f.write('\n')

# Calls SetDefaultVariable() with variables created with write_variables() for
# a given variable number
def format_setvar_single_call(var_num):
    var_name = 'var_%d_name' % var_num
    var_name_size = 'sizeof(%s)' % var_name
    var_bin = 'var_%d_bin' % var_num
    var_bin_size = 'sizeof(%s)' % var_bin
    var_guid = 'var_%d_guid' % var_num
    var_attributes = 'var_%d_attributes' % var_num
    return 'SetDefaultVariable(%s, %s, %s, %s, %s, %s)' % (
            var_name, var_name_size, var_bin, var_bin_size,
            var_guid, var_attributes)

# Fills in the body of InitializeDefaultVariables() with calls to set 
# each variable from the json file in the order they are found in the file.
def format_setvar_calls(variables):
    return ''.join([
'''
    res = %s;
    if (res != TEE_SUCCESS)
        return res;
''' % format_setvar_single_call(i) for i,_ in enumerate(variables)
    ])

# Defines the function InitializeDefaultVariables(), then fills it with a
# a set call for each default variable.
def write_end(f, variables):
    f.write('''
TEE_Result InitializeDefaultVariables( VOID ) {
    TEE_Result res;
%s
    DMSG("Done setting %d default variables");
    return TEE_SUCCESS;
}
''' % (format_setvar_calls(variables), len(variables)) )

num_args = len(sys.argv)
if num_args != 3:
    raise ValueError("Expecting 2 arguments (in.json, out.c)")
else:
    json_file_in = sys.argv[1]
    json_file_in_path = os.path.abspath(json_file_in)
    c_file_out = sys.argv[2]
    c_file_out_path = os.path.abspath(c_file_out)

print("defaultvars.py: Checking for variable file at", json_file_in_path)
if not os.path.isfile(json_file_in_path):
    raise FileNotFoundError("Could not find input " + str(json_file_in_path))

if os.path.isfile(c_file_out_path):
    print("defaultvars.py: Clearing output file at", c_file_out_path)
    os.remove(c_file_out_path)

with codecs.open(json_file_in_path, encoding='utf-8', mode='r') as json_file:
    variables = parse_json(json_file)

with open(c_file_out_path, 'w') as c_file:
    write_header(c_file, json_file_in_path)
    write_variables(c_file, variables)
    write_end(c_file, variables)
