# Using the type-conversion.json file
The [**type-conversion.json**](../../../src/wizardcalls/rsrc/data/type-conversion.json) exists to prevent invalid data types from being included in the source code. Often, various data types are just names for other default data types. By replacing the non-default data type with a default data type, we can prevent instances where developers must manually modify or automatement the adjustment of source code to account for the invalid data type.

An example is the [**SYSTEM_INFORMATION_CLASS**](https://ntdoc.m417z.com/system_information_class) enum. This enum is not included in the default header file and must be manually defined or included via a different header file. Since the enum is a range of sequential numbers from 0 - *, we can set the data type to **int** which will be accepted by the function.

## Updating the file
You may need to add your own type conversions. This can be done by accessing the **type-conversion.json** file in your modules installation directory. Open the file in a text editor & add your necessary conversions using the following syntax:

```json
{
    "DATA_TYPE_TO_REMOVE": "REPLACEMENT_DATA_TYPE"
}
```