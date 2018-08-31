-- Lua Dissector for VC-2
-- Author: James Weaver (james.barrett@bbc.co.uk)
--
-- To use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "vc2.lua"
-- 3) In Wireshark Preferences, under "Protocols", find VC2 and set the dynamic payload type to match the RTP
--    stream to be analysed
-- 4) Capture packets of an RTP stream
-- 5) "Decode As..." the UDP packets as RTP
-- 6) You will now see the VC-2 payload headers decoded within the RTP packets
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--
------------------------------------------------------------------------------------------------  
do  
    local vc2 = Proto("vc2", "VC-2")  
     
    local prefs = vc2.prefs  
    prefs.dyn_pt = Pref.uint("VC-2 dynamic payload type", 0, "The value > 95")  
 
    local F = vc2.fields

    F.ESN = ProtoField.uint16("vc2.ExtendedSequenceNumber","Extended Sequence Number",base.HEX,nil)
    F.BEG = ProtoField.bool("vc2.B","First Byte of Aux",8,{"True","False"},0x80)
    F.END = ProtoField.bool("vc2.E","Final Byte of Aux",8,{"True","False"},0x40)
    F.INT = ProtoField.bool("vc2.I","Picture Coding Mode",8,{"Interlaced","Progressive"},0x02)
    F.FID = ProtoField.bool("vc2.F","Field Identification",8,{"Second field","First field"},0x01)
    F.PC  = ProtoField.uint8("vc2.ParseCode", "Parse Code", base.HEX, { [0x00] = "Sequence Parameters", [0x10] = "End of Sequence", [0x20] = "Auxiliary Data", [0x30] = "Padding Data", [0xEC] = "HQ Picture Fragment" })
    F.SH  = ProtoField.bytes("vc2.SequenceHeader", "Coded Sequence Header Data")
    F.picnum      = ProtoField.uint32("vc2.PictureNumber", "Picture Number", base.DEC)
    F.prefix      = ProtoField.uint16("vc2.SlicePrefixBytes", "Slice Prefix Bytes", base.DEC)
    F.scalar      = ProtoField.uint16("vc2.SliceSizeScalar", "Slice Size Scalar", base.DEC)
    F.fraglength  = ProtoField.uint16("vc2.FragmentLength", "Fragment Length", base.DEC)
    F.noslices    = ProtoField.uint16("vc2.NumSlices", "Number of Slices")
    F.offset_x    = ProtoField.uint16("vc2.SliceOffsetX", "Slice Offset X")
    F.offset_y    = ProtoField.uint16("vc2.SliceOffsetY", "Slice Offset Y")
    F.codedslices = ProtoField.bytes("vc2.CodedSlices", "Coded Slice Data")
    F.transparam  = ProtoField.bytes("vc2.TransformParams", "Coded Transform Parameters")
    F.datalength  = ProtoField.uint32("vc2.DataLength", "Data Length")
    F.payloaddata = ProtoField.bytes("vc2.PayloadData", "Uncoded Payload Data")
 
    function vc2.dissector(tvb, pinfo, tree)
       local subtree = tree:add(vc2, tvb(),"VC-2 Data")
       local PC = tvb(3,1):uint()
       local noslices = 0
       subtree:add(F.ESN, tvb(0,2))
       if PC == 0xEC then
          subtree:add(F.INT, tvb(2,1))
          subtree:add(F.FID, tvb(2,1))
       elseif PC == 0x20 or PC == 0x30 then
          subtree:add(F.BEG, tvb(2,1))
          subtree:add(F.END, tvb(2,1))
       end
       subtree:add(F.PC,  tvb(3,1))
       if PC == 0x00 then
          subtree:add(F.SH, tvb(4))
       elseif PC == 0x20 or PC == 0x30 then
          datalength = tvb(4,4):uint()
          subtree:add(F.datalength, tvb(4,4))
          if PC == 0x20 and datalength > 0 then
              subtree:add(F.payloaddata, tvb(8))
          end
       elseif PC == 0xEC then
          subtree:add(F.picnum, tvb(4,4))
          subtree:add(F.prefix, tvb(8,2))
          subtree:add(F.scalar, tvb(10,2))
          subtree:add(F.fraglength, tvb(12,2))
          noslices = tvb(14,2):uint()
          if noslices == 0 then
             subtree:add(F.transparam, tvb(16))
          else
             subtree:add(F.noslices, tvb(14,2))
             subtree:add(F.offset_x, tvb(16,2))
             subtree:add(F.offset_y, tvb(18,2))
             subtree:add(F.codedslices, tvb(20))
          end
       end
    end
  
    -- register dissector to dynamic payload type dissectorTable  
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")  
    dyn_payload_type_table:add("vc2", vc2)  
  
    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")  
    local old_dissector = nil  
    local old_dyn_pt = 0  
    function vc2.init()  
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, vc2)  
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)  
                end  
            end  
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)  
            if (prefs.dyn_pt > 0) then  
                payload_type_table:add(prefs.dyn_pt, vc2)  
            end  
        end   
    end  
end
