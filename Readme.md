[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Iceberg&size=100&duration=500&pause=5000&color=0FFF0A&tru&vCenter=true&width=600&height=100&lines=Wizardcalls)](https://git.io/typing-svg)
[![Typing SVG](https://readme-typing-svg.herokuapp.com?font=Iceberg&weight=40&duration=500&pause=5000&color=0FFF0A&repeat=false&width=850&lines=An+indirect+syscall+generation+utility+for+C%2FC%2B%2B+implants+targeting+windows)](https://git.io/typing-svg)

## About

Wizardcalls is a code generation utility for C/C++ based implants targeting windows. Using wizardcalls, developers can quickly create a template containing desired syscalls for use in an implant via wizardcalls command line or scripting interfaces.

## Limitations
At this time, wizardcalls is only intended for use in Windows development environments. Linux is not currently supported but this feature is not off the table in the future.

Wizardcalls only supports x64 based implants at this time. x86 support could be added in the future.

## Installation
Wizardcalls can be installed manually from this repository or from PyPi.
###### Manual Installation
```
git clone https://github.com/wizardy0ga/wizardcalls
pip install .\wizardcalls
```
###### Install via PyPi
```
pip install wizardcalls
```

## Bugs, Feature & Other Requests
Feel free to open an issue for an issue for things like bugs & feature requests.

## Documentation
### Module
[Using wizardcalls from the command line](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/usage/command%20line.md)  
[Using wizardcalls in a script](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/usage/scripting.md)
### Template
[Using the wizardcalls source code in your implant](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/usage/template.md)
### Tutorials
[Writing an injector with wizardcalls](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/tutorials/Writing-an-injector-with-wizardcalls.md)  
[Writing a compilation script for the injector with wizardcalls](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/tutorials/Writing-a-compilation-script-for-the-injector-with-wizardcalls.md)

## Basic Usage
This section describes how wizardcalls can be used by developers. Wizardcalls offers two interfaces for developer usage, in a script & on the command line. The sections below provide a brief overview of both interfaces. See the linked documentation above for more inforamtion.

### Command Line
After installation, developers can interact with wizardcalls from the commandline via the **wizardcalls** command. The image below shows the current options available for building the template. Wizardcalls only requires the **--syscalls** argument for usage. See the [command line documentation](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/usage/command%20line.md) for more information.

![help output](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/img/help-output.png)

### Scripting
Hashycalls offers an interface for developers to automate their implant's build routine via the **WizardCalls** object. More information can be found in the [scipting](https://github.com/wizardy0ga/WizardCalls/blob/main/docs/en/usage/scripting.md) documentation.

```py
WizardCalls(
    syscalls                 = [ 'NtAllocateVirtualMemory','NtFreeVirtualMemory','NtWriteVirtualMemory','NtCreateThreadEx','NtWaitForSingleObject' ]
    , syscall_list_name      = 'pSyscallz'
    , hash_seed              = 10000
    , globals                = True
    , hash_algo              = 'djb2'
    , randomize_jump_address = True
    , debug                  = True
)
```
