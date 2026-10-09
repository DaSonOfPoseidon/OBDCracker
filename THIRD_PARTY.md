# Third-party test data

Test vectors ported from other projects, so our codecs are checked against implementations we didn't write. No
third-party code ships in the crates.

| Source | Commit | License | Used in |
|---|---|---|---|
| [pylessard/python-can-isotp](https://github.com/pylessard/python-can-isotp) | `5593c219f35e739554d743a98d3af68c9332da31` | MIT | `crates/obdcracker-core/tests/third_party.rs` (ISO-TP frames and reassembly) |
| [pylessard/python-udsoncan](https://github.com/pylessard/python-udsoncan) | `78e85f1b5dac968b6a2d478fce9c0cc5adba2b50` | MIT | `crates/obdcracker-core/tests/third_party.rs` (UDS 0x22, 0x19, negative responses) |

Both projects are MIT licensed:

> MIT License
>
> Copyright (c) 2017 Pier-Yves Lessard
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
> documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
> rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
> persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
> Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
> COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
