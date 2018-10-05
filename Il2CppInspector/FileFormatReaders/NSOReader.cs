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
	    private bool _arm32;
	    private uint _nsoVersion;
	    private uint _reserved1;
	    private byte[] _reserved2;
	    private uint _flags;
	    private NSOSegmentHeader _textSegmentHeader;
	    private NSOSegmentHeader _roDataSegmentHeader;
	    private NSOSegmentHeader _dataSegmentHeader;
	    private uint _moduleOffset;
	    private uint _moduleFileSize;
	    private uint _bssSize;
	    private byte[] _buildId;
	    private NSORoDataRelativeExtent _roDataRelativeExtentsOfApiInfo;
	    private NSORoDataRelativeExtent _roDataRelativeExtentsOfDynstr;
	    private NSORoDataRelativeExtent _roDataRelativeExtentsOfDynsym;
	    private NSOMod _mod;
	    private List<NSODynamic> _dynamics;
	    private byte[] _textSection;
	    private byte[] _roDataSection;
	    private byte[] _dataSection;
		private byte[] _fullCode;

		public NSOReader(Stream stream) : base(stream) {}

        public override string Arch {
            get {
	            return _arm32 ? "ARM" : "ARM64";
            }
        }

        protected override bool Init() {
            // Check for NSO0 signature "NSO0"
            if (ReadUInt32() != 0x304F534E)
                return false;

			// NSO Version is always 0
	        _nsoVersion = ReadUInt32();
			if (_nsoVersion != 0x00)
		        return false;

			// Reserved (Unused)
	        _reserved1 = ReadUInt32();

			// Flags
	        _flags = ReadUInt32();

			// .text SegmentHeader
	        _textSegmentHeader = new NSOSegmentHeader();
	        _textSegmentHeader.FileOffset = ReadUInt32();
	        _textSegmentHeader.MemoryOffset = ReadUInt32();
	        _textSegmentHeader.DecompressedSize = ReadUInt32();

			// Module offset (calculated by sizeof(header))
	        _moduleOffset = ReadUInt32();

			// .rodata SegmentHeader
			_roDataSegmentHeader = new NSOSegmentHeader();
	        _roDataSegmentHeader.FileOffset = ReadUInt32();
	        _roDataSegmentHeader.MemoryOffset = ReadUInt32();
	        _roDataSegmentHeader.DecompressedSize = ReadUInt32();

			// Module file size
	        _moduleFileSize = ReadUInt32();

			// .data SegmentHeader
			_dataSegmentHeader = new NSOSegmentHeader();
	        _dataSegmentHeader.FileOffset = ReadUInt32();
	        _dataSegmentHeader.MemoryOffset = ReadUInt32();
	        _dataSegmentHeader.DecompressedSize = ReadUInt32();

			// bssSize
	        _bssSize = ReadUInt32();

			// Value of "build id" from ELF's GNU .note section. Contains variable sized digest, up to 32bytes.
	        _buildId = ReadBytes(32);

			// Compressed Sizes
	        _textSegmentHeader.CompressedSize = ReadUInt32();
	        _roDataSegmentHeader.CompressedSize = ReadUInt32();
	        _dataSegmentHeader.CompressedSize = ReadUInt32();

			// Reserved (Padding)
	        _reserved2 = ReadBytes(28);

			// Relative Extents
	        _roDataRelativeExtentsOfApiInfo = new NSORoDataRelativeExtent();
	        _roDataRelativeExtentsOfApiInfo.RegionRoDataOffset = ReadUInt32();
	        _roDataRelativeExtentsOfApiInfo.RegionSize = ReadUInt32();

	        _roDataRelativeExtentsOfDynstr = new NSORoDataRelativeExtent();
	        _roDataRelativeExtentsOfDynstr.RegionRoDataOffset = ReadUInt32();
	        _roDataRelativeExtentsOfDynstr.RegionSize = ReadUInt32();

	        _roDataRelativeExtentsOfDynsym = new NSORoDataRelativeExtent();
	        _roDataRelativeExtentsOfDynsym.RegionRoDataOffset = ReadUInt32();
	        _roDataRelativeExtentsOfDynsym.RegionSize = ReadUInt32();

			// Section Hashes
	        _textSegmentHeader.SHA256Hash = ReadBytes(32);
	        _roDataSegmentHeader.SHA256Hash = ReadBytes(32);
	        _dataSegmentHeader.SHA256Hash = ReadBytes(32);

			// Decompress .text Section
			Position = _textSegmentHeader.FileOffset;
	        if ((_flags & 1) != 0)
		        _textSection = Decompress(ReadBytes((int)_textSegmentHeader.CompressedSize), (int)_textSegmentHeader.DecompressedSize);
	        else
		        _textSection = ReadBytes((int)_textSegmentHeader.DecompressedSize);

	        // Decompress .rodata Section
			Position = _roDataSegmentHeader.FileOffset;
	        if ((_flags & 2) != 0)
				_roDataSection = Decompress(ReadBytes((int)_roDataSegmentHeader.CompressedSize), (int)_roDataSegmentHeader.DecompressedSize);
			else
		        _roDataSection = ReadBytes((int)_roDataSegmentHeader.DecompressedSize);

			// Decompress .data Section
			Position = _dataSegmentHeader.FileOffset;
	        if ((_flags & 4) != 0)
		        _dataSection = Decompress(ReadBytes((int) _dataSegmentHeader.CompressedSize), (int)_dataSegmentHeader.DecompressedSize);
	        else
		        _dataSection = ReadBytes((int)_dataSegmentHeader.DecompressedSize);
			
			// Map Sections to Memory
			using (var fullCodeStream = new MemoryStream())
			using (var fullCodeWriter = new BinaryWriter(fullCodeStream))
			{
				fullCodeWriter.Write(_textSection);
				uint roOffset = _roDataSegmentHeader.MemoryOffset;
				if (roOffset >= fullCodeWriter.BaseStream.Position)
					fullCodeWriter.Seek((int)(roOffset - fullCodeWriter.BaseStream.Position), SeekOrigin.Current);
				else
				{
					Console.WriteLine("Truncating .text?");
					fullCodeWriter.Seek((int)roOffset, SeekOrigin.Begin);
				}

				fullCodeWriter.Write(_roDataSection);
				uint dataOffset = _dataSegmentHeader.MemoryOffset;
				if (dataOffset > fullCodeWriter.BaseStream.Position)
					fullCodeWriter.Seek((int)(dataOffset - fullCodeWriter.BaseStream.Position), SeekOrigin.Current);
				else
					Console.WriteLine("Truncating .rodata?");

				fullCodeWriter.Write(_dataSection);
				fullCodeWriter.Flush();
				_fullCode = fullCodeStream.ToArray();
			}
			
	        using (var codeStream = new MemoryStream(_fullCode, false))
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

		        _mod = codeReader.ReadObject<NSOMod>();
		        _mod.DynamicOffset += modOffset;
		        _mod.BssStartOffset += modOffset;
		        _mod.BssEndOffset += modOffset;
		        _mod.UnwindOffset += modOffset;
		        _mod.UnwindEndOffset += modOffset;
		        _mod.ModuleOffset += modOffset;

		        _arm32 = (codeReader.ReadUInt64(_mod.DynamicOffset) > 0xFFFFFFFF || codeReader.ReadUInt64(_mod.DynamicOffset + 0x10) > 0xFFFFFFFF);

		        //dynamic = codeReader.ReadObject<NSODynamic>(mod.DynamicOffset);

		        uint flatSize = _dataSegmentHeader.MemoryOffset + _dataSegmentHeader.DecompressedSize;

		        _dynamics = new List<NSODynamic>();
		        codeReader.BaseStream.Seek(_mod.DynamicOffset, SeekOrigin.Begin);
		        for (uint i = 0; i < (flatSize - _mod.DynamicOffset) / 0x10; i++)
		        {
			        NSODynamic dynamic = new NSODynamic();
					dynamic.Tag = (NSODynamicTag)(_arm32 ? codeReader.ReadUInt32() : codeReader.ReadUInt64());
			        if (dynamic.Tag == NSODynamicTag.DT_NULL)
				        break;
			        dynamic.Value = _arm32 ? codeReader.ReadUInt32() : codeReader.ReadUInt64();
					//if ((int)dynamic.Tag > 0 && (int)dynamic.Tag < 31)
					_dynamics.Add(dynamic);
		        }
	        }

	        return true;
        }

	    public override ulong[] GetFunctionTable()
	    {
		    ulong globalOffsetTable = 0;
		    ulong arrayOffset = 0;
		    ulong arraySize = 0;
		    foreach (NSODynamic dynamic in _dynamics)
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
			
		    GlobalOffset = globalOffsetTable;

		    using (var codeStream = new MemoryStream(_fullCode, false))
		    using (var codeReader = new BinaryObjectReader(codeStream))
		    {
			    if (_arm32)
			    {
				    return ArrayUtil.ConvertArray<ulong, uint>(codeReader.ReadArray<uint>((uint) arrayOffset,
					    (int) (arraySize / 4)));
			    }
			    else
			    {
				    return codeReader.ReadArray<ulong>((uint) arrayOffset, (int) (arraySize / 8));
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
