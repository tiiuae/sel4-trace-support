# sel4-trace-support

A collection of programs to convert and merge seL4 tracebuffer to/with ftrace logs (WIP).

### Build

```
git clone git@github.com:tiiuae/sel4-trace-support.git
cd ./sel4-trace-support
mkdir build && cd ./build
cmake ..
make
```

### Usage

#### sel4-extract

A tool for converting seL4 tracebuffer logs to ftrace compatible binary format.


   ```
   ./sel4-extract/sel4-extract [fname in] [fname out]
   ```
#### sel4-ftrace-merge

A tool for merging converted seL4 tracebuffer logs with trace-cmd\kernelshark logs.

   ```
   ./sel4_trace_merge/sel4_trace_merge [ftrace_fname in] [sel4_fname in]
   ```

### Format description

trace-cmd binary format is described at `trace-cmd.dat` [man page][1]  

ftrace binary described in following parts of trace-cmd.dat (**_Please notice: currently formats are hardcoded, but they should be parsed from following places_**):  

+ HEADER INFO FORMAT - contains a page (4096b) header format and event header formats. Event header format can also be found `debugfs/tracing/events/header_event`-file

   PAGE HEADER FORMAT example (debug output of `sel4-ftrace-merge` tool):
   ```
   [DBG]: ------------- Header Page Format -------------
   [DBG]: Header page format magic: header_page
   [DBG]: Header page format size: 205
   [DBG]: Page Header Format:
           field: u64 timestamp;   offset:0;       size:8; signed:0;
           field: local_t commit;  offset:8;       size:8; signed:1;
           field: int overwrite;   offset:8;       size:1; signed:1;
           field: char data;       offset:16;      size:4080;      signed:0;
   ```
   
   Field descriptions:
   ```
      timestamp -- timestamp of a 1st entry in this page
      commit    -- number of bytes used in the page (up to 4080)
      overwrite -- don't know what is it for =(
      data      -- data content of the page
   ```

   EVENT HEADER FORMAT example (debug output of `sel4-ftrace-merge` tool):
   ```
   [DBG]: ------------- Header Event Format -------------
   [DBG]: Header event magic: header_event
   [DBG]: Header event size: 205
   [DBG]: Header Event Format:
   # compressed entry header
           type_len    :    5 bits
           time_delta  :   27 bits
           array       :   32 bits

           padding     : type == 29
           time_extend : type == 30
           time_stamp : type == 31
           data max type_len  == 28
   ```

   Field description:
   ```
      type_len   -- array size in int32 (4 bytes) words, up to 27 (28, 29, 30 and 31 -- Special Cases)
      time_delta -- time difference with timestamp in PAGE HEADER (for 1st entry is zero)
      array      -- array content of an entry
      
      Secial Cases:
      28 -- data max type_len -- don't know what is it for =(
      29 -- padding           -- probably just padding, no useful data in array ? =(
      30 -- time_extend       -- in case if time difference more than 27 bits, we use that to handle time difference*
      31 -- time_stamp        -- probably just time_stamp? =(
      
      * `array[1] = (time_delta & TIME_DELTA_MASK) >> TS_SHIFT`, 
         this one is only one actually useful and well described case
         (even in `trace-cmd` code, so other cases probably **dead**)
   ```
   
+ FTRACE EVENT FORMATS - contains an events format descriptions, also could be found here: `debugfs/tracing/events/ftrace/<event>/format`

   We need `FUNCTION` event, here is an example (debug output of `sel4-ftrace-merge` tool):
   ```[DBG]:
   [DBG]: ------------- Ftrace Event Formats -------------
   [DBG]: Ftrace event formats count: 15
   .....
   [DBG]: Event Format #8 size: 0x1cc
   [DBG]: Event Format:
   name: function
   ID: 1
   format:
           field:unsigned short common_type;       offset:0;       size:2; signed:0;
           field:unsigned char common_flags;       offset:2;       size:1; signed:0;
           field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
           field:int common_pid;   offset:4;       size:4; signed:1;

           field:unsigned long ip; offset:8;       size:8; signed:0;
           field:unsigned long parent_ip;  offset:16;      size:8; signed:0;

   print fmt: " %ps <-- %ps", (void *)REC->ip, (void *)REC->parent_ip
   ```

   Field descriptions:
   
   ```
      common_type          -- should be equal to the function event ID ( ID: 1 here)
      common_flags         -- some flags
      common_preempt_count -- don't know what is it for =(
      common_pid           -- linux process ID, for seL4 we use here some dedicated PID (like: 999, also hardcoded =)
      ip                   -- function IP, for for seL4 we use here some dedicated IP ( also hardcoded =)
      parent_ip            -- parent function IP (caller), for for seL4 we use here some dedicated IP ( also hardcoded =)
   ```
   
+ PAGE FORMAT example:
   ```
   PAGE_HEADER {
      ...
      data {
        EVENT_HEADER {
           ...
           array {
              EVENT_FORMAT {}
           }
        },
        EVENT_HEADER {
           ...
           array {
              EVENT_FORMAT {}
           }
        },
        EVENT_HEADER {
           ...
           array {
              EVENT_FORMAT {}
           }
        },
        ...
      }
   }
   ```

+ PROCESS INFORMATION   -- section contains current processes information from: `debugfs/tracing/saved_cmdlines`

   Here we need to add our seL4 `common_pid` and it's name

+ KALLSYMS INFORMATION  -- section contains current kernel address to function maps from: `/proc/kallsyms`

   Here we need to add our seL4 `ip`, `parent_ip` and their names

### Useful links

[man trace-cmd](https://man7.org/linux/man-pages/man5/trace-cmd.dat.5.html)  
[trace-cmd binary format description](https://man7.org/linux/man-pages/man5/trace-cmd.dat.5.html)  
[trace-cmd git](https://git.kernel.org/pub/scm/utils/trace-cmd/trace-cmd.git/)  
[libtraceevent git](https://git.kernel.org/pub/scm/libs/libtrace/libtraceevent.git/) -- this one is what actually we need to use to parse and recreate all headers info, etc.  
[libtracefs git](https://git.kernel.org/pub/scm/libs/libtrace/libtracefs.git)  

### Further reading
[libtracecmd, libtracefs and libtraceevent -- Introduction to the Linux kernel tracing libraries](https://www.socallinuxexpo.org/sites/default/files/presentations/Introduction%20to%20tracing%20libraries.pdf)  
[Common Tracing Platform -- Let’s put our brains together](https://tracingsummit.org/ts/2018/files/Tracingsummit2018-libftrace-rostedt.pdf)  
[Tracing the Linux kernel with ftrace, trace-cmd and kernelshark](https://sergioprado.blog/tracing-the-linux-kernel-with-ftrace/)

[1]: https://man7.org/linux/man-pages/man5/trace-cmd.dat.5.html
