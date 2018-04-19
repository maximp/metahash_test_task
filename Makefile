.PHONY: clean All

All:
	@echo "----------Building project:[ mh_test - Release ]----------"
	@"$(MAKE)" -f  "mh_test.mk"
clean:
	@echo "----------Cleaning project:[ mh_test - Release ]----------"
	@"$(MAKE)" -f  "mh_test.mk" clean
