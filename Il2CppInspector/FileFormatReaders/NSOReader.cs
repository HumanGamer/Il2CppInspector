/*
    Copyright 2017 Katy Coe - http://www.hearthcode.org - http://www.djkaty.com

    All rights reserved.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using LZ4;
using NoisyCowStudios.Bin2Object;

namespace Il2CppInspector
{
    internal class NSOReader : FileFormatReader<NSOReader>
    {
	    private bool arm32;
	    private uint nsoVersion;
	    private uint reserved1;
	    private byte[] reserved2;
	    private uint flags;
	    private NSOSegmentHeader textSegmentHeader;
	    private NSOSegmentHeader roDataSegmentHeader;
	    private NSOSegmentHeader dataSegmentHeader;
	    private uint moduleOffset;
	    private uint moduleFileSize;
	    private uint bssSize;
	    private byte[] buildId;
	    private NSORoDataRelativeExtent roDataRelativeExtentsOfApiInfo;
	    private NSORoDataRelativeExtent roDataRelativeExtentsOfDynstr;
	    private NSORoDataRelativeExtent roDataRelativeExtentsOfDynsym;
	    private NSOMod mod;
	    private List<NSODynamic> dynamics;
	    private byte[] textSection;
	    private byte[] roDataSection;
	    private byte[] dataSection;
		private byte[] fullCode;

		public NSOReader(Stream stream) : base(stream) {}

        public override string Arch {
            get {
	            return "ARM";
            }
        }

        protected override bool Init() {
            // Check for NSO0 signature "NSO0"
            if (ReadUInt32() != 0x304F534E)
                return false;

			// NSO Version is always 0
	        nsoVersion = ReadUInt32();
			if (nsoVersion != 0x00)
		        return false;

			// Reserved (Unused)
	        reserved1 = ReadUInt32();

			// Flags
	        flags = ReadUInt32();

			// .text SegmentHeader
	        textSegmentHeader = new NSOSegmentHeader();
	        textSegmentHeader.FileOffset = ReadUInt32();
	        textSegmentHeader.MemoryOffset = ReadUInt32();
	        textSegmentHeader.DecompressedSize = ReadUInt32();

			// Module offset (calculated by sizeof(header))
	        moduleOffset = ReadUInt32();

			// .rodata SegmentHeader
			roDataSegmentHeader = new NSOSegmentHeader();
	        roDataSegmentHeader.FileOffset = ReadUInt32();
	        roDataSegmentHeader.MemoryOffset = ReadUInt32();
	        roDataSegmentHeader.DecompressedSize = ReadUInt32();

			// Module file size
	        moduleFileSize = ReadUInt32();

			// .data SegmentHeader
			dataSegmentHeader = new NSOSegmentHeader();
	        dataSegmentHeader.FileOffset = ReadUInt32();
	        dataSegmentHeader.MemoryOffset = ReadUInt32();
	        dataSegmentHeader.DecompressedSize = ReadUInt32();

			// bssSize
	        bssSize = ReadUInt32();

			// Value of "build id" from ELF's GNU .note section. Contains variable sized digest, up to 32bytes.
	        buildId = ReadBytes(32);

			// Compressed Sizes
	        textSegmentHeader.CompressedSize = ReadUInt32();
	        roDataSegmentHeader.CompressedSize = ReadUInt32();
	        dataSegmentHeader.CompressedSize = ReadUInt32();

			// Reserved (Padding)
	        reserved2 = ReadBytes(28);

			// Relative Extents
	        roDataRelativeExtentsOfApiInfo = new NSORoDataRelativeExtent();
	        roDataRelativeExtentsOfApiInfo.RegionRoDataOffset = ReadUInt32();
	        roDataRelativeExtentsOfApiInfo.RegionSize = ReadUInt32();

	        roDataRelativeExtentsOfDynstr = new NSORoDataRelativeExtent();
	        roDataRelativeExtentsOfDynstr.RegionRoDataOffset = ReadUInt32();
	        roDataRelativeExtentsOfDynstr.RegionSize = ReadUInt32();

	        roDataRelativeExtentsOfDynsym = new NSORoDataRelativeExtent();
	        roDataRelativeExtentsOfDynsym.RegionRoDataOffset = ReadUInt32();
	        roDataRelativeExtentsOfDynsym.RegionSize = ReadUInt32();

			// Section Hashes
	        textSegmentHeader.SHA256Hash = ReadBytes(32);
	        roDataSegmentHeader.SHA256Hash = ReadBytes(32);
	        dataSegmentHeader.SHA256Hash = ReadBytes(32);

			// Decompress .text Section
			Position = textSegmentHeader.FileOffset;
	        if ((flags & 1) != 0)
		        textSection = Decompress(ReadBytes((int)textSegmentHeader.CompressedSize), (int)textSegmentHeader.DecompressedSize);
	        else
		        textSection = ReadBytes((int)textSegmentHeader.DecompressedSize);

	        // Decompress .rodata Section
			Position = roDataSegmentHeader.FileOffset;
	        if ((flags & 2) != 0)
				roDataSection = Decompress(ReadBytes((int)roDataSegmentHeader.CompressedSize), (int)roDataSegmentHeader.DecompressedSize);
			else
		        roDataSection = ReadBytes((int)roDataSegmentHeader.DecompressedSize);

			// Decompress .data Section
			Position = dataSegmentHeader.FileOffset;
	        if ((flags & 4) != 0)
		        dataSection = Decompress(ReadBytes((int) dataSegmentHeader.CompressedSize), (int)dataSegmentHeader.DecompressedSize);
	        else
		        dataSection = ReadBytes((int)dataSegmentHeader.DecompressedSize);
			
			// Map Sections to Memory
			using (var fullCodeStream = new MemoryStream())
			using (var fullCodeWriter = new BinaryWriter(fullCodeStream))
			{
				fullCodeWriter.Write(textSection);
				uint roOffset = roDataSegmentHeader.MemoryOffset;
				if (roOffset >= fullCodeWriter.BaseStream.Position)
					fullCodeWriter.Seek((int)(roOffset - fullCodeWriter.BaseStream.Position), SeekOrigin.Current);
				else
				{
					Console.WriteLine("Truncating .text?");
					fullCodeWriter.Seek((int)roOffset, SeekOrigin.Begin);
				}

				fullCodeWriter.Write(roDataSection);
				uint dataOffset = dataSegmentHeader.MemoryOffset;
				if (dataOffset > fullCodeWriter.BaseStream.Position)
					fullCodeWriter.Seek((int)(dataOffset - fullCodeWriter.BaseStream.Position), SeekOrigin.Current);
				else
					Console.WriteLine("Truncating .rodata?");

				fullCodeWriter.Write(dataSection);
				fullCodeWriter.Flush();
				fullCode = fullCodeStream.ToArray();
			}
			
	        using (var codeStream = new MemoryStream(fullCode, false))
			using (var codeReader = new BinaryObjectReader(codeStream))
	        {
		        uint modOffset = codeReader.ReadUInt32(0x4);
				
		        // Mod
		        codeReader.BaseStream.Seek(modOffset, SeekOrigin.Begin);
		        uint modMagic = codeReader.ReadUInt32();
		        if (modMagic != 0x30444F4D)
				{
					return false;
		        }

		        mod = codeReader.ReadObject<NSOMod>();
		        mod.DynamicOffset += modOffset;
		        mod.BssStartOffset += modOffset;
		        mod.BssEndOffset += modOffset;
		        mod.UnwindOffset += modOffset;
		        mod.UnwindEndOffset += modOffset;
		        mod.ModuleOffset += modOffset;

		        arm32 = (codeReader.ReadUInt64(mod.DynamicOffset) > 0xFFFFFFFF || codeReader.ReadUInt64(mod.DynamicOffset + 0x10) > 0xFFFFFFFF);

		        //dynamic = codeReader.ReadObject<NSODynamic>(mod.DynamicOffset);

		        uint flatSize = dataSegmentHeader.MemoryOffset + dataSegmentHeader.DecompressedSize;

		        dynamics = new List<NSODynamic>();
		        codeReader.BaseStream.Seek(mod.DynamicOffset, SeekOrigin.Begin);
		        for (uint i = 0; i < (flatSize - mod.DynamicOffset) / 0x10; i++)
		        {
			        NSODynamic dynamic = new NSODynamic();
					dynamic.Tag = (NSODynamicTag)(arm32 ? codeReader.ReadUInt32() : codeReader.ReadUInt64());
			        if (dynamic.Tag == NSODynamicTag.DT_NULL)
				        break;
			        dynamic.Value = arm32 ? codeReader.ReadUInt32() : codeReader.ReadUInt64();
					//if ((int)dynamic.Tag > 0 && (int)dynamic.Tag < 31)
					dynamics.Add(dynamic);
		        }
	        }

	        return true;
        }

	    public override uint[] GetFunctionTable()
	    {
		    ulong globalOffsetTable = 0;
		    ulong arrayOffset = 0;
		    ulong arraySize = 0;
		    foreach (NSODynamic dynamic in dynamics)
		    {
			    if (dynamic.Tag == NSODynamicTag.DT_PLTGOT)
			    {
				    globalOffsetTable = dynamic.Value;
			    } else if (dynamic.Tag == NSODynamicTag.DT_INIT_ARRAY)
			    {
				    arrayOffset = dynamic.Value;
			    } else if (dynamic.Tag == NSODynamicTag.DT_INIT_ARRAYSZ)
			    {
				    arraySize = dynamic.Value;
			    }
		    }
		    if (globalOffsetTable == 0)
			    throw new InvalidOperationException("Unable to get GLOBAL_OFFSET_TABLE from PT_DYNAMIC");

			// TODO: Support ulong
		    GlobalOffset = (uint)globalOffsetTable;

		    using (var codeStream = new MemoryStream(fullCode, false))
		    using (var codeReader = new BinaryObjectReader(codeStream))
		    {
				if (arm32)
					return codeReader.ReadArray<uint>((uint)arrayOffset, (int)(arraySize / 4));
			    else
			    {
					// TODO: Support 64bit
				    ulong[] result64 = codeReader.ReadArray<ulong>((uint) arrayOffset, (int) (arraySize / 8));
				    uint[] result = new uint[result64.Length];
				    for (int i = 0; i < result64.Length; i++)
				    {
					    result[i] = (uint) result64[i];
				    }

				    return result;
			    }
		    }
	    }

		/*public override uint[] GetFunctionTable() {
            Position = pFuncTable;
            var addrs = new List<uint>();
            uint addr;
            while ((addr = ReadUInt32()) != 0)
                addrs.Add(MapVATR(addr) & 0xfffffffc);
            return addrs.ToArray();
        }

        public override void FinalizeInit(Il2CppBinary il2cpp) {
            il2cpp.MethodPointers = il2cpp.MethodPointers.Select(x => x - 1).ToArray();
        }

        public override uint MapVATR(uint uiAddr) {
            if (uiAddr == 0)
                return 0;

            var section = sections.First(x => uiAddr - GlobalOffset >= x.BaseMemory &&
                                              uiAddr - GlobalOffset < x.BaseMemory + x.SizeMemory);
            return uiAddr - section.BaseMemory - GlobalOffset + section.BaseImage;
        }*/

	    private static byte[] Decompress(byte[] compressed, int uncompressedSize)
	    {
			byte[] outputBuffer = new byte[uncompressedSize];
		    LZ4Codec.Decode(compressed, 0, compressed.Length, outputBuffer, 0, outputBuffer.Length, true);

		    return outputBuffer;
	    }
	}
}
