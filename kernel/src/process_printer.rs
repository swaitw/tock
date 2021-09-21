//! Tools for displaying process state.

use core::fmt::Write;

use crate::process::Process;
use crate::utilities;

/// A context token that the caller must pass back to us. This allows us to
/// track where we are in the print operation.
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct ProcessPrinterContext {
    /// The overall print message is broken in to chunks so that it can be fit
    /// in a small buffer that is called multiple times. This tracks which chunk
    /// we are in so we can print the next block.
    offset: usize,
}

pub(crate) struct BinaryToWriteWrapper<'a> {
    writer: &'a mut dyn core::fmt::Write,
}

impl<'a> BinaryToWriteWrapper<'a> {
    pub(crate) fn new(writer: &'a mut dyn core::fmt::Write) -> BinaryToWriteWrapper {
        BinaryToWriteWrapper { writer }
    }
}

impl<'a> utilities::offset_binary_write::OffsetBinaryWrite for BinaryToWriteWrapper<'a> {
    fn write_buffer(&mut self, b: &[u8]) -> Result<usize, ()> {
        unsafe {
            let _ = self.writer.write_str(core::str::from_utf8_unchecked(b));
        }
        Ok(b.len())
    }
}

struct WriteToBinaryWrapper<'a> {
    binary_writer: &'a mut dyn utilities::offset_binary_write::OffsetBinaryWrite,
    index: usize,
    offset: usize,
    bytes_remaining: bool,
}

impl<'a> WriteToBinaryWrapper<'a> {
    fn new(
        binary_writer: &'a mut dyn utilities::offset_binary_write::OffsetBinaryWrite,
    ) -> WriteToBinaryWrapper {
        WriteToBinaryWrapper {
            binary_writer,
            index: 0,
            offset: 0,
            bytes_remaining: false,
        }
    }

    fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    fn get_index(&self) -> usize {
        self.index
    }

    fn bytes_remaining(&self) -> bool {
        self.bytes_remaining
    }
}

impl<'a> core::fmt::Write for WriteToBinaryWrapper<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let string_len = s.len();
        if self.index + string_len < self.offset {
            // We are still waiting for `self.offset` bytes to be send before we
            // actually start printing.
            self.index += string_len;
            Ok(())
        } else {
            // We need to be printing at least some of this.
            let start = if self.offset <= self.index {
                // We're past our offset, so we can display this entire str.
                0
            } else {
                // We want to start in the middle.
                self.offset - self.index
            };

            let to_send = string_len - start;

            let ret = self
                .binary_writer
                .write_buffer(&(s).as_bytes()[start..string_len]);

            match ret {
                Ok(bytes_sent) => {
                    self.index += bytes_sent + start;

                    if to_send > bytes_sent {
                        self.bytes_remaining = true;
                    }

                    Ok(())
                }
                Err(()) => Err(core::fmt::Error),
            }
        }
    }
}

/// Trait for creating a custom "process printer" that formats process state in
/// some sort of presentable format.
///
/// Typically, implementations will display process state in a text UI over some
/// sort of terminal.
///
/// This trait also allows for experimenting with different process display
/// formats. For example, some use cases might want more or less detail, or to
/// encode the process state in some sort of binary format that can be expanded
/// into a human readable format later. Other cases might want to log process
/// state to nonvolatile storage rather than display it immediately.
pub trait ProcessPrinter {
    fn print(
        &self,
        process: &dyn Process,
        writer: &mut dyn utilities::offset_binary_write::OffsetBinaryWrite,
        context: Option<ProcessPrinterContext>,
    ) -> Option<ProcessPrinterContext>;
}

/// A Process Printer that displays a process as a human-readable string.
pub struct ProcessPrinterText {}

impl ProcessPrinterText {
    pub fn new() -> ProcessPrinterText {
        ProcessPrinterText {}
    }
}

impl ProcessPrinter for ProcessPrinterText {
    fn print(
        &self,
        process: &dyn Process,
        writer: &mut dyn utilities::offset_binary_write::OffsetBinaryWrite,
        context: Option<ProcessPrinterContext>,
    ) -> Option<ProcessPrinterContext> {
        let offset = context.map_or(0, |c| c.offset);

        // Process statistics
        let events_queued = process.pending_tasks();
        let syscall_count = process.debug_syscall_count();
        let dropped_upcall_count = process.debug_dropped_upcall_count();
        let restart_count = process.get_restart_count();

        let addresses = process.get_addresses();
        let sizes = process.get_sizes();

        let process_struct_memory_location = addresses.sram_end
            - sizes.grant_pointers
            - sizes.upcall_list
            - sizes.process_control_block;
        let sram_grant_size = process_struct_memory_location - addresses.sram_grant_start;

        let mut bww = WriteToBinaryWrapper::new(writer);
        bww.set_offset(offset);

        let _ = bww.write_fmt(format_args!(
            "\
                 𝐀𝐩𝐩: {}   -   [{:?}]\
                 \r\n Events Queued: {}   Syscall Count: {}   Dropped Upcall Count: {}\
                 \r\n Restart Count: {}\
                 \r\n",
            process.get_process_name(),
            process.get_state(),
            events_queued,
            syscall_count,
            dropped_upcall_count,
            restart_count,
        ));

        let _ = match process.debug_syscall_last() {
            Some(syscall) => bww.write_fmt(format_args!(" Last Syscall: {:?}\r\n", syscall)),
            None => bww.write_str(" Last Syscall: None\r\n"),
        };

        let _ = bww.write_fmt(format_args!(
            "\
                 \r\n\
                 \r\n ╔═══════════╤══════════════════════════════════════════╗\
                 \r\n ║  Address  │ Region Name    Used | Allocated (bytes)  ║\
                 \r\n ╚{:#010X}═╪══════════════════════════════════════════╝\
                 \r\n             │ Grant Ptrs   {:6}\
                 \r\n             │ Upcalls      {:6}\
                 \r\n             │ Process      {:6}\
                 \r\n  {:#010X} ┼───────────────────────────────────────────\
                 \r\n             │ ▼ Grant      {:6}\
                 \r\n  {:#010X} ┼───────────────────────────────────────────\
                 \r\n             │ Unused\
                 \r\n  {:#010X} ┼───────────────────────────────────────────",
            addresses.sram_end,
            sizes.grant_pointers,
            sizes.upcall_list,
            sizes.process_control_block,
            process_struct_memory_location,
            sram_grant_size,
            addresses.sram_grant_start,
            addresses.sram_app_brk,
        ));

        if !bww.bytes_remaining() {
            match addresses.sram_heap_start {
                Some(sram_heap_start) => {
                    let sram_heap_size = addresses.sram_app_brk - sram_heap_start;
                    let sram_heap_allocated = addresses.sram_grant_start - sram_heap_start;

                    let _ = bww.write_fmt(format_args!(
                        "\
                         \r\n             │ ▲ Heap       {:6} | {:6}{}     S\
                         \r\n  {:#010X} ┼─────────────────────────────────────────── R",
                        sram_heap_size,
                        sram_heap_allocated,
                        exceeded_check(sram_heap_size, sram_heap_allocated),
                        sram_heap_start,
                    ));
                }
                None => {
                    let _ = bww.write_str(
                        "\
                         \r\n             │ ▲ Heap            ? |      ?               S\
                         \r\n  ?????????? ┼─────────────────────────────────────────── R",
                    );
                }
            }
        }

        if !bww.bytes_remaining() {
            match (addresses.sram_heap_start, addresses.sram_stack_top) {
                (Some(sram_heap_start), Some(sram_stack_top)) => {
                    let sram_data_size = sram_heap_start - sram_stack_top;
                    let sram_data_allocated = sram_data_size as usize;

                    let _ = bww.write_fmt(format_args!(
                        "\
                         \r\n             │ Data         {:6} | {:6}               A",
                        sram_data_size, sram_data_allocated,
                    ));
                }
                _ => {
                    let _ = bww.write_str(
                        "\
                         \r\n             │ Data              ? |      ?               A",
                    );
                }
            }
        }

        if !bww.bytes_remaining() {
            match (addresses.sram_stack_top, addresses.sram_stack_bottom) {
                (Some(sram_stack_top), Some(sram_stack_bottom)) => {
                    let sram_stack_size = sram_stack_top - sram_stack_bottom;
                    let sram_stack_allocated = sram_stack_top - addresses.sram_start;

                    let _ = bww.write_fmt(format_args!(
                        "\
                         \r\n  {:#010X} ┼─────────────────────────────────────────── M\
                         \r\n             │ ▼ Stack      {:6} | {:6}{}",
                        sram_stack_top,
                        sram_stack_size,
                        sram_stack_allocated,
                        exceeded_check(sram_stack_size, sram_stack_allocated),
                    ));
                }
                _ => {
                    let _ = bww.write_str(
                        "\
                         \r\n  ?????????? ┼─────────────────────────────────────────── M\
                         \r\n             │ ▼ Stack           ? |      ?",
                    );
                }
            }
        }

        if !bww.bytes_remaining() {
            let flash_protected_size = addresses.flash_non_protected_start - addresses.flash_start;
            let flash_app_size = addresses.flash_end - addresses.flash_non_protected_start;

            let _ = bww.write_fmt(format_args!(
                "\
                 \r\n  {:#010X} ┼───────────────────────────────────────────\
                 \r\n             │ Unused\
                 \r\n  {:#010X} ┴───────────────────────────────────────────\
                 \r\n             .....\
                 \r\n  {:#010X} ┬─────────────────────────────────────────── F\
                 \r\n             │ App Flash    {:6}                        L\
                 \r\n  {:#010X} ┼─────────────────────────────────────────── A\
                 \r\n             │ Protected    {:6}                        S\
                 \r\n  {:#010X} ┴─────────────────────────────────────────── H\
                 \r\n",
                addresses.sram_stack_bottom.unwrap_or(0),
                addresses.sram_start,
                addresses.flash_end,
                flash_app_size,
                addresses.flash_non_protected_start,
                flash_protected_size,
                addresses.flash_start
            ));
        }

        if bww.bytes_remaining() {
            let new_context = ProcessPrinterContext {
                offset: bww.get_index(),
            };
            Some(new_context)
        } else {
            None
        }
    }
}

fn exceeded_check(size: usize, allocated: usize) -> &'static str {
    if size > allocated {
        " EXCEEDED!"
    } else {
        "          "
    }
}
