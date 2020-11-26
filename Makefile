CP := cp

RM := rm

CXX := g++

SRCS := $(wildcard src/*.cpp)

OBJS := $(patsubst src/%.cpp,obj/%.o,$(SRCS))

MKDIR := mkdir

TARGET := bin/netfi

CXXFLAGS := -Wall -O2

INCLUDES := -I"./header" 

INSTALL_DIR := /usr/local

# Build
all: libs $(TARGET) install

libs:
	@$(MKDIR) -p obj
	@$(MKDIR) -p bin
	@echo '# Start build processes'

obj/%.o: src/%.cpp
	@echo ' └─Building file: $<'
	@$(CXX) $(INCLUDES) $(CXXFLAGS) -c $< -o $@ -MD -lpcap
 
$(TARGET) : $(OBJS)
	@$(CXX) $(INCLUDES) $(CXXFLAGS) $(OBJS) -o $(TARGET) -lpcap -lpthread
	@echo '# Finished successfully building NetFI'

# Clean
clean: uninstall
	@$(RM) -rf ./obj
	@$(RM) -rf ./bin
	@echo '# Finished successfully cleaning NetFI'

# Install
install: 
	@$(MKDIR) -p $(INSTALL_DIR)/include/NetFI
	@$(MKDIR) -p $(INSTALL_DIR)/etc/NetFI/logDIR
	@$(CP) header/* $(INSTALL_DIR)/include/NetFI
	@$(MKDIR) -p $(INSTALL_DIR)/bin
	@$(CP) bin/* $(INSTALL_DIR)/bin
	@echo '# Installation complete!'

# Uninstall
uninstall:
	@$(RM) -rf $(INSTALL_DIR)/include/NetFI
	@$(RM) -f $(INSTALL_DIR)/bin/netfi
	@$(RM) -rf $(INSTALL_DIR)/etc/NetFI
	@echo '# Uninstallation complete!'



