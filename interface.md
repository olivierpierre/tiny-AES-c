# What are the attacks one could achieve on a "non-sanitized" version of the crosss compartment interface??

## Bad message type

Make sure that the switch case on message type will exit without running anything, and the server will drop the request and become available for the next one.

## Bad encryption mode

No library function to call for that one, make sure to exit the switch case, don't return a buffer to the client (need to let the client know with a return error code).

## Wrong Buffers Size

- For CBC/CTR: buffer should be a multiple of AES_BLOCKLEN otherwise we get a buffer overflow on it
- For ECB encrypt/decrypt operations, the buffer size should always *be* AES_BLOCKLEN

Need to return an error code to the client in case these things happen, because the server won't be returning a buffer.