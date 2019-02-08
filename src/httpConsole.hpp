#ifndef HTTPCONSOLE_HPP_
#define HTTPCONSOLE_HPP_

pthread_t startConsoleBG(int port);
void registerGpuName(int index, const char *name);
void stopConsoleBG();
void setHashRate(int index, float v);
void setFrequency(int frequency);


#endif /* HTTPCONSOLE_HPP_ */
