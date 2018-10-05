using System;
using System.Collections.Generic;
using System.Text;
using NoisyCowStudios.Bin2Object;

namespace Il2CppInspector
{
	internal class NSOSegmentHeader
	{
		public uint FileOffset;
		public uint MemoryOffset;
		public uint CompressedSize;
		public uint DecompressedSize;
		[ArrayLength(FixedSize = 32)]
		public byte[] SHA256Hash;
	}

	internal class NSORoDataRelativeExtent
	{
		public uint RegionRoDataOffset;
		public uint RegionSize;
	}

	internal class NSOMod
	{
		public uint DynamicOffset;
		public uint BssStartOffset;
		public uint BssEndOffset;
		public uint UnwindOffset;
		public uint UnwindEndOffset;
		public uint ModuleOffset;
	}

	internal class NSODynamic
	{
		public NSODynamicTag Tag;
		public ulong Value;
	}

	internal enum NSODynamicTag
	{
		DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ,
		DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI, DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL,
		DT_RELSZ, DT_RELENT, DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY,
		DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS
	}

	/*internal class NSODynamic
	{
		public uint Name;
		public uint Type;
		public uint Flags;
		public uint Address;
		public uint Offset;
		public uint Size;
		public uint Link;
		public uint Info;
		public uint AddressAlign;
		public uint EntrySize;
	}*/
}
