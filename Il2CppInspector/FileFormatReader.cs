/*
    Copyright 2017 Katy Coe - http://www.hearthcode.org - http://www.djkaty.com

    All rights reserved.
*/

using System;
using System.Collections.Generic;
using System.IO;
using NoisyCowStudios.Bin2Object;

namespace Il2CppInspector
{
    public interface IFileFormatReader
    {
        BinaryObjectReader Stream { get; }
        uint NumImages { get; }
        IEnumerable<IFileFormatReader> Images { get; }
        IFileFormatReader this[uint index] { get; }
        long Position { get; set; }
        string Arch { get; }
        ulong GlobalOffset { get; }
        ulong[] GetFunctionTable();
        U ReadMappedObject<U>(ulong uiAddr) where U : new();
        U[] ReadMappedArray<U>(ulong uiAddr, int count) where U : new();
        ulong MapVATR(ulong uiAddr);
        void FinalizeInit(Il2CppBinary il2cpp);

        byte[] ReadBytes(int count);
        ulong ReadUInt64();
        uint ReadUInt32();
        ushort ReadUInt16();
        byte ReadByte();
    }

    internal class FileFormatReader<T> : BinaryObjectReader, IFileFormatReader where T : FileFormatReader<T>
    {
        public FileFormatReader(Stream stream) : base(stream) { }

        public BinaryObjectReader Stream => this;

        public uint NumImages { get; protected set; } = 1;

        public ulong GlobalOffset { get; protected set; }

        public virtual string Arch => throw new NotImplementedException();

        public IEnumerable<IFileFormatReader> Images {
            get {
                for (uint i = 0; i < NumImages; i++)
                    yield return this[i];
            }
        }

        public static T Load(string filename) {
            using (var stream = new FileStream(filename, FileMode.Open))
                return Load(stream);
        }

        public static T Load(Stream stream) {
            stream.Position = 0;
            var pe = (T) Activator.CreateInstance(typeof(T), stream);
            return pe.Init() ? pe : null;
        }

        // Confirm file is valid and set up RVA mappings
        protected virtual bool Init() => throw new NotImplementedException();

        // Choose a sub-binary within the image for multi-architecture binaries
        public virtual IFileFormatReader this[uint index] {
            get {
                if (index == 0)
                    return this;
                throw new IndexOutOfRangeException("Binary image index out of bounds");
            }
        }

        // Find search locations in the machine code for Il2Cpp data
        public virtual ulong[] GetFunctionTable() => throw new NotImplementedException();

        // Map an RVA to an offset into the file image
        // No mapping by default
        public virtual ulong MapVATR(ulong uiAddr) => uiAddr;

        // Retrieve object(s) from specified RVA(s)
        public U ReadMappedObject<U>(ulong uiAddr) where U : new() {
            return ReadObject<U>((long)MapVATR(uiAddr));
        }

        public U[] ReadMappedArray<U>(ulong uiAddr, int count) where U : new() {
            return ReadArray<U>((long)MapVATR(uiAddr), count);
        }

        // Perform file format-based post-load manipulations to the IL2Cpp data
        public virtual void FinalizeInit(Il2CppBinary il2cpp) { }
    }
}