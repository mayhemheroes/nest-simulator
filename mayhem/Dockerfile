FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake python-is-python3 libgsl-dev  libltdl-dev  libncurses-dev  libreadline-dev  python3-all-dev  python3-numpy  python3-scipy  python3-matplotlib  python3-nose  python3-junitparser  python3-mpi4py  openmpi-bin  libopenmpi-dev python3-pip clang
RUN pip3 install cython

COPY . /repo
WORKDIR /repo/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=/install -Dwith-python=OFF
RUN make -j8
RUN make install
RUN clang++ /repo/mayhem/fuzz_ends_with.cpp -I /repo/libnestutil/ -fsanitize=fuzzer,address -o /fuzz

FROM ubuntu:22.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libgsl-dev  libltdl-dev  libreadline-dev  openmpi-bin  libopenmpi-dev libgomp1
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_ends_with
