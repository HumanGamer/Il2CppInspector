using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppInspector
{
	public static class IOExtensions
	{
		public static long ReadInt64(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadInt64();
		}

		public static ulong ReadUInt64(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadUInt64();
		}

		public static int ReadInt32(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadInt32();
		}

		public static uint ReadUInt32(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadUInt32();
		}

		public static short ReadInt16(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadInt16();
		}

		public static ushort ReadUInt16(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadUInt16();
		}

		public static byte ReadByte(this BinaryReader self, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadByte();
		}

		public static byte[] ReadBytes(this BinaryReader self, int count, long address)
		{
			self.BaseStream.Position = address;
			return self.ReadBytes(count);
		}

		public static void WriteNullBytes(this BinaryWriter self, long count)
		{
			byte[] bytes = new byte[count];
			self.Write(bytes);
		}
	}
}
