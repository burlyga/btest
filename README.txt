121216 - Version 160:
	- fix partial/incomplete io handling
	- fix out of range bug
	- add latency level

120520 - Version 156:
	- 32 bit complication fixes
	- several valiataion mode fixes
	- incomplete IO handling

120315 - Version 155:
	- fix dedup calc for progressive fills

120301 - Version 154:
	- fix block + md verify bug, format md area

120229 - Version 153:
	- fix small bug in async init
	- verify only (no exit on verify errors) exit with non zero code at
	  the end of the veririfaction.

120212 - Version 151:
	- cleanup IO modes
	- add sgio_direct and direct_sync modes
	- add CVS reports

120131 - Version 150:
	- add warmup, update doc
	- fix timeout check
	- fix total stats
	- cleanup states

111123 - Version 141:
	- add timeout check, update doc

111121 - Version 140:
	- add static data patterns, compression control

110919 - Version 131:
	- add progressive dedup fill mode (-g)

110830 - Version 130:
    - fix doc (usage)
    - bump btest version v130
    - dedup modulo to a simple int
    - fix seq+aio (see multi threads)
    - fix seq and multi threads - will follow instead of replicating offsets
    - imporve md alloc, handle md alloc failure (was a infinite loop)
    - Fix extension, add hash pool tests
    - fix dedup stamps such that each device will gets its own symbol set

110525 - Version 121-1:
-fix async summary report bug (duration should be =/ ndev)

110406 - Version 121:
- Add exit on end of file option
- Multi threaded validation mode support (-T nthread with -C)
- Fix for random IO rate != 0 or 100 (didn't work - buf inserted in version 120)
- For option -C and -m: if a single taget file is used, the parameter is the path not the base
- Fix wrong message when opening a meta data file (was "joining" even if ref was zero)
- Fix option -o offset (didn't work - buf inserted in version 120)
- Update docs

110327 - Version 120: (1.2):
- Major cleanup
- AIO stats fixes
- Verification modes

This binary was compiled on RHEL6 x64 and requires libaio. In it doesn't work for you system try to compile it yourself.
