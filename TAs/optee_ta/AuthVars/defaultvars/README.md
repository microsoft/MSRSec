# Default Variables

Setting `CFG_AUTHVARS_DEFAULT_VARS=y` will cause the AuthVars TA to ensure a set of default variables are present during first boot.

If the TA detects that there is no pre-existing non-volatile storage it will set the default variables as if it received a call from UEFI. The name, GUID, attributes, and binary data of the variables are defined in a JSON file, passed via `CFG_DEFAULT_VARS_JSON=/path/to/vars.json`.

## JSON File
The JSON file pointed to by `CFG_DEFAULT_VARS_JSON=/path/to/vars.json` defines which variables will be added.

* **`name:`** ECS-2 encodable string. Since the JSON file is saved as UTF-8 the unicode characters can be placed directly in the string.
* **`bin_path:`** Path to the binary contents of the variable. If the variable is authenticated this binary should include the authentication headers. **If** the path is not absolute, it is taken relative to the AuthVars TA root directory (`MSRSec/TAs/optee_ta/AuthVars`).
* **`guid:`** The variable GUID, must be valid C syntax. May also be one of the well known GUIDs `EFI_IMAGE_SECURITY_DATABASE_GUID` or `EFI_GLOBAL_VARIABLE`.
* **`attributes:`** The attributes the variable should be saved with (from `uefidefs.h`). Must be valid C syntax.

The variables will be saved into the AuthVar TA in the order they are found in the JSON file.

```json
{
    "variables": [
        {
            "name": "Default Volatile Variable Example / (Supports ECS-2 characters ✍)",
            "bin_path": "defaultvars/example.bin",
            "guid": "{0xe4b297c1, 0x507d, 0x407f, {0xbe,0x4a,0xe9,0x25,0x68,0x69,0x25,0x14}}",
            "attributes": "EFI_VARIABLE_APPEND_WRITE | EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS"
        }
    ]
}
```

### Examples
Two examples are included, along with binaries.

The first example, `defaultvars_example.json`, is included by default if `CFG_DEFAULT_VARS_JSON` is left unset. It adds a single variable (as shown above).

The second example, `defaultvars_secureboot_example.json` can be used by setting `CFG_DEFAULT_VARS_JSON=defaultvars/defaultvars_secureboot_example.json`. This example automatically enables secure boot using **NON-SECURE** keys from the [TurnkeySecurity](https://github.com/ms-iot/security/tree/master/TurnkeySecurity) repository. They are included for example purposes only. A production image must use newly generated signing keys.

### Text Encoding of Variable Names
The JSON file **must be `UTF-8` encoded**, as the python script explicitly decodes it as UTF-8. The JSON file may contain *MOST*, **but not all** unicode characters. UEFI uses ECS-2 encoding for its strings, a subset of UTF-16. ECS-2 does not allow 4-byte characters to be stored, so no UTF-16 surrogate pairs. Valid ECS-2 values are: `[0x0000, 0xd800] ∪ [0xdfff, 0xffff]`. The python script used to compile the variables will check the validity of the encoding for each character.


## Compilation
At compilation time `defaultvars.py` runs, taking the JSON file found at `CFG_DEFAULT_VARS_JSON`, and creating the file `$(sub-dir-out)/defaultvars_encoding.c`. This C file encodes each variable in the JSON file as a set of C variables:
```c
WCHAR var_0_name[] = L"Abcd" "\x1234" "5678";
GUID var_0_guid = {0x12345678,0x9abc,0xdef0,{0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0}};
ATTRIBUTES var_0_attributes = "EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS";
BYTE var_0_bin[] = { 0x0, 0x1, 0x2, 0x3, ... };

WCHAR var_2_name[] = L"XYZ" "\x1234" "5678";
...
```

The generated C file also contains the definition for `InitializeDefaultVariables()`, which is defined in `defaultvars.h`, and is called during initialization of the TA in `AuthVarInitStorage()` if and only if there is no pre-existing non-volatile storage pressent (assuming `CFG_DEFAULT_VARS_JSON=y`).

```c
TEE_Result InitializeDefaultVariables( VOID ) {
    TEE_Result res;

    res = SetDefaultVariable(var_0_name, sizeof(var_0_name), var_0_bin, sizeof(var_0_bin), var_0_guid, var_0_attributes);
    if (res != TEE_SUCCESS)
        return res;

    res = SetDefaultVariable(var_1_name, sizeof(var_1_name), var_1_bin, sizeof(var_1_bin), var_1_guid, var_1_attributes);
    if (res != TEE_SUCCESS)
        return res;

    DMSG("Done setting 2 default variables");
    return TEE_SUCCESS;
}
```
