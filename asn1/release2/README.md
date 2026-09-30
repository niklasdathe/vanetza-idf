# ETSI ITS ASN.1

The ASN.1 files in this directory are a slightly patched subset of the files published by ETSI for ITS Release 2.
You can find the original files on [ETSI Forge](https://forge.etsi.org/rep/ITS/asn1). Our changes are documented below.
These files are distributed under a permissive license:

> Copyright 2019 ETSI
>
> Redistribution and use in source and binary forms, with or without 
> modification, are permitted provided that the following conditions are met:
> 1. Redistributions of source code must retain the above copyright notice, 
>    this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, 
>    this list of conditions and the following disclaimer in the documentation 
>    and/or other materials provided with the distribution.
> 3. Neither the name of the copyright holder nor the names of its contributors 
>    may be used to endorse or promote products derived from this software without 
>    specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
> ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
> WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
> IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
> INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
> BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
> DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
> LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
> OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
> OF THE POSSIBILITY OF SUCH DAMAGE.


# Changes

## CDD

TS 102 894-2 V2.5.1 (2026-09, forge tag v2.5.1, OID major 4 minor 4), published SHA-256
`a15d9e7d1f498e0a382d81b03051c666b20eea31f52ae55c0abd3e49f905a70a`. Removed obsolete `ActionID` and `StationID` data elements. The generated file names clash with those of `ActionId` and `StationId` on case-insensitive filesystems.

## CPM

Updated CDD imports (to V2.5.1, major 4 minor 4: the published imports name one version without `WITH SUCCESSORS`).

## VAM

Updated CDD imports of `VAM-PDU-Descriptions.asn` and `motorcyclist-special-container.asn` to V2.5.1 (major 4
minor 4): asn1c resolves imports by object identifier and does not treat a new major version as a successor.

## Regeneration

`vanetza/asn1/Dockerfile` pins ubuntu 24.04 for the asn1c build (ubuntu:latest, 26.04 in 2026-09, produced an
asn1c that segfaults). ITS Release 2 was regenerated 2026-09-29 against CDD V2.5.1; the same pipeline first
reproduced the committed V2.4.1 output byte for byte. CDD V2.5.1 adds `GoodsType`, which POIM also defines, so
asn1c now qualifies both (`ETSI-ITS-CDD_GoodsType`, `POIM-ParkingAvailability_GoodsType`).

## Security

`TS103097v221.asn` and `TS103097v221-Extension.asn` are TS 103 097 V2.2.1 (2026-03, forge tag v2.2.1; published
SHA-256 `245a3c10…ff72` and `b94c9b37…eb1a`, Tables A.1/A.2). The core module is unchanged. The extension module
imports IEEE `Extension` as `IeeeExtension`, the name `vanetza/asn1/fetch_ieee_asn1_files.cmake` gives the IEEE type.
That step now fetches IEEE 1609.2 from forge tag `v2025`, the version TS 103 097 V2.2.1 profiles (Tables A.3/A.4).

The security codec (`vanetza/asn1/security`, prefix `Vanetza_Security_`) is generated from these, TS 102 941 V2.2.1
(the CA message module only: the ITS-S message modules redefine the same PDU names) and IEEE 1609.2-2025/1609.2.1.
It replaces the Release 1 set (TS 103 097 V1.3.1): the `security-headerinfo-1609dot2a.patch` workaround is gone,
because HeaderInfo now carries `pduFunctionalType` and `contributedExtensions` natively. `vanetza/asn1/security/r2`
(`Vanetza_Security2_`, TS 103 097 V2.1.1) was regenerated against IEEE 1609.2 v2025 as well; the upstream build still compiles it as a component, the ESP-IDF port no longer uses it.
