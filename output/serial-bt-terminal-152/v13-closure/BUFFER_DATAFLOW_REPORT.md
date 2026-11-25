# Buffer Dataflow Report (v1.3)

> No semantic interpretation of bytes; no BMW/RFCOMM payload claims from names.

## Counts

- **buffer_ops**: `6`
- **transport_paths_reaching_buffer**: `3`
- **transport_paths_reaching_consumer_producer**: `0`
- **transport_paths_reaching_decoder_encoder**: `0`

## Decoder / Encoder

- **decoder_candidates**: 0
- **serializer_candidates**: 0
- **primitive_decoding_sites**: 0
- **interpretation**: Primitive int/short results after read are INFERENCE candidates for byte-level handling only. Method names (decode/parse/Bcl/Etch/BMW) are search indicators, never protocol proof.
- **protocol_semantics**: UNKNOWN

## Connections (sample)

| Source | Operation | Target | Identity | Method | Class |
|---|---|---|---|---|---|
| input:I1 | Ljava/io/InputStream;->read([B)I | v1 | REGISTER | La00;->run()V | FACT |
| input:I1 | Ljava/io/InputStream;->read([B)I | v1 | REGISTER | La00;->run()V | FACT |
| output:O1 | Ljava/io/OutputStream;->write([B)V | v2 | REGISTER | La00;->e([B)V | FACT |
| output:O1 | Ljava/io/OutputStream;->write([B)V | v2 | REGISTER | La00;->e([B)V | FACT |
| output:O1 | Ljava/io/OutputStream;->write([B)V | v2 | REGISTER | La00;->e([B)V | FACT |
| input:I1 | Ljava/io/InputStream;->read([B)I | v1 | REGISTER | La00;->run()V | FACT |
