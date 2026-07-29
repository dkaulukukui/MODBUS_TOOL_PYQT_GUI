To Do list:
- (empty)

Completed in v1.0:
- add version number to GUI and code — `__version__` in modbus_tool.py, shown in the window title,
  next to the protocol mode selector, and logged at startup
- it looks like there may be some error in the CRC calcs for func 16 — the CRC routine itself was
  correct; monitor mode mis-framed func 15/16 (and multi-register read) responses by reading them
  with the request layout, so the wrong number of bytes was captured and the CRC check failed.
  Request vs response is now resolved by CRC-checking the 8-byte fixed-size interpretation first,
  and bytes read past the end of a frame are carried into the next one instead of being discarded.
- allow option for LSB or MSB payloads — "Payload Byte Order" selector; applies to 16-bit register
  data on send and decode only (addresses, quantities and byte counts stay big-endian per spec)
- allow user to disable automatic CRC calcs for custom function payload — "Auto-calculate CRC for
  custom packet" checkbox (RTU); when unchecked the custom packet is sent exactly as typed
