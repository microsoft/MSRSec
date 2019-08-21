# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import os, sys, json, codecs

# Variables are encoded as:
#       BYTE <VAR_NUM>_name[] = L"ECS\x002d2\x20COMPATIBLE\x20STRING";
#       BYTE <VAR_NUM>_bin[] = { 0x0, 0x1, 0x2, ... };
#       GUID <VAR_NUM>_guid = {0x12345678,0x9abc,0xdef0,{0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}};
#       ATTRIBUTES <VAR_NUM>_attributes = <ATTR1 | ATTR2 | ... >;
#
# The function add_vars() will add each variable in the order it was found in the json by calling
# the add_default_var() function from default_var_utils.c


VALID_TYPES = ['EFI_VARIABLE_NON_VOLATILE',
                'EFI_VARIABLE_BOOTSERVICE_ACCESS',
                'EFI_VARIABLE_RUNTIME_ACCESS',
                'EFI_VARIABLE_HARDWARE_ERROR_RECORD',
                'EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS',
                'EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS',
                'EFI_VARIABLE_APPEND_WRITE']

#define EFI_IMAGE_SECURITY_DATABASE_GUID \
WELL_KNOWN_GUIDS = [
    ('EFI_IMAGE_SECURITY_DATABASE_GUID','{ 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0xe, 0x67, 0x65, 0x6f } }'),
    ('EFI_GLOBAL_VARIABLE','{ 0x8BE4DF61, 0x93CA, 0x11d2, { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C } }')]

def convert_to_wchar(char):
    if ord(char) >= 0xd800 and ord(char) <= 0xdfff:
        raise ValueError("Invalid ECS2 encoding (UTF-16 surrogate) for character '%c'" % char)
    if ord(char) > 0xffff:
        raise ValueError("Invalid ECS2 encoding for character '%c', to large for ECS2" % char)
    if ((ord(char) in range(ord('a'), ord('z'))) or
            (ord(char) in range(ord('A'), ord('Z'))) or
            (ord(char) in range(ord('0'), ord('9')))):
        return char
    else:
        # Generates something of the form: <" "\x0123" ">
        return (r'" "\x' + ('%04x' % ord(char)) + '" "' )

# We could compile unicode strings here, but it is easier to convert to hex representation
# instead of handing escaping everything correctly. Also verify we are not encoding any 
# 4 byte characters which ECS2 can't handle.
def format_wchar_string(string):
    return 'L"' + ''.join(convert_to_wchar(c) for c in string) + '"'

def format_byte_array(bytes):
    line_length = 16
    return '{\n\t%s\n}' % (''.join(['0x%02x, ' % byte + ('\n\t' if ((i+1) % line_length == 0) else '') for i, byte in enumerate(bytes)]))

# Generate tupples of the form:
#   (name, <binary data>, guid, attributes)
def parse_json(json_file):
    json_data = json_file.read()
    json_data = json.loads(str(json_data))
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

def write_header(f):
    f.write('/* Automatically generated file created by default_vars.py */\n')
    f.write('/* Add hard-coded variables to the image by editing default_vars.json */\n')
    f.write('#include <varops.h>\n')
    f.write('#include <default_var_utils.h>\n')


#       CHAR16 var_<VAR_NUM>_name[] = { 0x0, 0x1, 0x2, ... };
#       BYTE var_<VAR_NUM>_bin[] = { 0x0, 0x1, 0x2, ... };
#       GUID var_<VAR_NUM>_guid = {0x12345678,0x9abc,0xdef0,{0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}};
#       ATTRIBUTES var_<VAR_NUM>_attributes = <ATTR1 | ATTR2 | ... >;
def write_variables(f, variables):
    for i,var in enumerate(variables):
        f.write(('CHAR16 var_%d_name[] = ' % i) + var[0] + ";\n")
        f.write(('BYTE var_%d_bin[] = ' % i) + var[1] + ";\n")
        f.write(('GUID var_%d_guid = ' % i) + var[2] + ";\n")
        f.write(('ATTRIBUTES var_%d_attributes = ' % i) + var[3] + ";\n")
        f.write('\n')

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

def format_setvar_calls(variables):
    return ''.join([
'''
    res = %s;
    if (res != TEE_SUCCESS)
        return res;
''' % format_setvar_single_call(i) for i,_ in enumerate(variables)
    ])

def write_end(f, variables):
    f.write('''
TEE_Result InitializeDefaultVariables( VOID ) {
    TEE_Result res;
%s
    return TEE_SUCCESS;
}
''' % format_setvar_calls(variables))



num_args = len(sys.argv)
if num_args != 3:
#    raise ValueError("Expecting 2 arguments (in.json, out.c)")
    json_file_in = 'foo'
    c_file_out = 'bar.c'
    json_file_in_path = os.path.abspath(os.path.join(os.getcwd(), json_file_in))
    c_file_out_path = os.path.abspath(os.path.join(os.getcwd(), c_file_out))
else:
    json_file_in = sys.argv[1]
    json_file_in_path = os.path.abspath(os.path.join(os.getcwd(), json_file_in))
    c_file_out = sys.argv[2]
    c_file_out_path = os.path.abspath(os.path.join(os.getcwd(), c_file_out))

print("Checking for variable file in", json_file_in_path)
if os.path.isfile(json_file_in_path):
    print("Parsing variables from %s" % json_file_in_path)
else:
    raise FileNotFoundError("Could not find input " + str(json_file_in_path))

if os.path.isfile(c_file_out_path):
    os.remove(c_file_out_path)

with codecs.open(json_file_in_path, encoding='utf-8', mode='r') as json_file:
    variables = parse_json(json_file)

with open(c_file_out_path, 'w') as c_file:
    write_header(c_file)
    write_variables(c_file, variables)
    write_end(c_file, variables)
