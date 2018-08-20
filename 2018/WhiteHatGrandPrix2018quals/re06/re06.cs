using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RE06
{
    class Program
    {
        public static int mod(int m, int e, int n)
        {
            int[] array = new int[100];
            int num = 0;
            do
            {
                array[num] = e % 2;
                num++;
                e /= 2;
            }
            while (e != 0);
            int num2 = 1;
            for (int i = num - 1; i >= 0; i--)
            {
                num2 = num2 * num2 % n;
                bool flag = array[i] == 1;
                if (flag)
                {
                    num2 = num2 * m % n;
                }
            }
            return num2;
        }
        public static string Enc(string s, int e, int n)
        {
            int[] array = new int[s.Length];
            for (int i = 0; i < s.Length; i++)
            {
                array[i] = (int)s[i];
            }
            int[] array2 = new int[array.Length];
            for (int i = 0; i < array.Length; i++)
            {
                array2[i] = mod(array[i], e, n);
            }
            string text = "";
            for (int i = 0; i < array.Length; i++)
            {
                text += (char)array2[i];
            }
            return Convert.ToBase64String(Encoding.Unicode.GetBytes(text));
        }
        public static string check()
        {
            string encoded;
            string key = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAlj";
            string flag = "";
            bool found;
            while (true)
            {
                found = false;
                for (int i = 32; i < 128; i++)
                {
                    for (int i2 = 32; i2 < 128; i2++)
                    {
                        for (int i3 = 32; i3 < 128; i3++)
                        {
                            encoded = Enc(flag + (char)i + (char)i2 + (char)i3, 9157, 41117).Replace("=", "");
                            if (encoded == key)
                            {
                                flag = flag + (char)i + (char)i2 + (char)i3;
                                Console.WriteLine("Flag: {0}", flag);
                                return flag;
                            }
                            if (encoded == key.Substring(0, encoded.Length))
                            {
                                flag = flag + (char)i + (char)i2 + (char)i3;
                                Console.WriteLine("Flag: {0}", flag);
                                found = true;
                                break;
                            }
                        }
                    }
                    if (found)
                    {
                        break;
                    }
                }
            }
        }
        static void Main(string[] args)
        {
            string key = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAlj";
            string encoded;
            string flag = check();
            while (true)
            {
                for (int i = 32; i < 128; i++)
                {
                    encoded = Enc(flag + (char)i, 9157, 41117);
                    if (encoded == key + "LGQ=")
                    {
                        flag = flag + (char)i;
                        Console.WriteLine("Final Flag: {0}", flag);
                        Console.ReadLine();
                    }
                }
                Console.WriteLine("Not found!");
                break;

            }

        }
    }
}
