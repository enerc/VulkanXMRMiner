#ifndef HTTPCONSOLE_HPP_
#define HTTPCONSOLE_HPP_

#ifdef __MINGW32__
HANDLE startConsoleBG(int port);
#else
pthread_t startConsoleBG(int port);
#endif
void registerGpuName(int index, const char *name);
void stopConsoleBG();
void setHashRate(int index, float v);
void setFrequency(int frequency);


#endif /* HTTPCONSOLE_HPP_ */
