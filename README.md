# rfc8450-vc2-dissector

Wireshark plugin to parse RTP streams implementing the VC-2 HQ payload specification

## Introduction

This plugin accompanies the release of [RFC 8450](https://datatracker.ietf.org/doc/draft-ietf-payload-rtp-vc2hq/) which defines the mechanism to carry VC-2 HQ coded video using Real Time Protocol (RTP).

Using this plugin in conjunction with the [Wireshark protocol analyzer](https://www.wireshark.org/) provides the means to verify that an implementation is correctly producing the required header fields for the VC-2 RTP packets.

## Installation

### Requirements

*   [Wireshark](https://www.wireshark.org/)

### Steps

1.  Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua.
2.  Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal and Global plugin directories.
3.  After putting this dissector in the proper folder, "About Wireshark/Plugins" should list "vc2.lua".

### Usage

1.  In Wireshark Preferences, under "Protocols", find VC2 and set the dynamic payload type to match the RTP stream to be analysed.
2.  Capture packets of an RTP stream.
3.  "Decode As..." the UDP packets as RTP.
4.  You will now see the VC-2 payload headers decoded within the RTP packets.

## Contributing

Whilst we do not expect contributions to this plugin, we would appreciate reporting of any bugs via GitHub's Issues. We will endeavour to investigate and resolve issues as soon as possible.

## License

See [LICENSE](LICENSE)
