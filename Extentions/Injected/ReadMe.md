This folders Dlls are meant to be injected into a process

HeapRead - Dumps the heap of a process that its injected into (Heap)

Sly.dll - Hooks a function name and an optional single-step (Full function trace)

Sly Must also use a Config.txt to pull a function name so you can change it on the fly

vehList.dll - Checks for active exception handlers in the remote process and returns the
veh handler address

DebuggerInjector.dll coming very soon. It will have a janky licensing model, and will not work
if this debugger is not running, and also will check into a webserver to make sure its 
good to run. All things here are for educational purposes only, and I will quickly shut the 
Injector down if I see any misuse in the server logs.
