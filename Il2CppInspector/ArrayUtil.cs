using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Il2CppInspector
{
	public static class ArrayUtil
	{
		public static T[] ConvertArray<T, K>(K[] original)
		{
			T[] result = new T[original.Length];
			for (int i = 0; i < original.Length; i++)
			{
				result[i] = (T)(object)original[i];
			}

			return result;
		}
	}
}
