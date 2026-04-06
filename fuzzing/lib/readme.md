# Welcome to the D(ata) S(tructure) Lab! 📊🏗️🔬

DSLab is a small framework that generates fuzzers and profilers for arbitrary Zig data structures using a comptime-declared operations schema.

Inside the DSLab, you can find fuzzed and profiled implementations of various data structures, mostly written with Zig. In addition to that, you can find a small library for writing data structure fuzzers and profilers. Everything is open-sourced under the MIT License so feel free to pull what you need into your own projects as you see fit!

## Features ✨

The invariant fuzzing method that this repo provides the tools to implement is extremely powerful for rooting out hard-to-find bugs and recreating them with perfect replicability. Likewise, the instrumentation-based profiling this repo provides the tools to implement assists in accurately measuring the performance of your data structure's functions once correctness has been demonstrated through fuzzing.

The amount of boilerplate needed to write these fuzzers and profilers is reduced drastically by the APIs provided here, as Zig's comptime is used heavily to allow for a declarative schema to be defined in the form of a Zig comptime struct that provides the API with function pointers that get automatically wired up to an *ops table*, an array of function pointers that wrap your operations specified in the schema, that can be randomly indexed into at runtime for fuzzing and profiling through a single `step()` function.

## Repo Structure 🗂️

The project repo is laid out as follows:
- 📁 `fuzz/` - Contains `fuzz.zig`, the root module for the public fuzzing API.
- 📁 `prof/` - Contains `prof.zig`, the root module for the public profiling API.
- 📁 `shared/` - Contains `log.zig` and `makeOp.zig`, the root modules that are shared by the fuzzing and profiling APIs.
- 📁 `<data_structure>/` - Each data structure is contained in a subdirectory named after the data structure contained. These subdirectories are laid out as follows:
    - 📄 `<data_structure>/build.zig` - The build script for both the fuzzer and profiler harnesses.
    - 📄 `<data_structure>/fuzz.zig` - The fuzzer harness implementation.
    - 📄 `<data_structure>/prof.zig` - The profiler harness implementation.
    - 📄 `<data_structure>/<data_structure>.zig` - The data structure implementation.

The purpose of this layout is to make it so you can easily find just the data structure(s) you need and install them.

## How to Write Data Structure Fuzzers and Profilers ✍️

The `Fuzzer` and `Profiler` struct factory functions, implemented in `fuzz/fuzz.zig` and `prof/prof.zig`, take two comptime arguments. The first is the data structure you wish to fuzz/profile, and the second is a schema of sorts. Here is an example:

```Zig
const Fuzzer = fuzz.Fuzzer(RedBlackTree, .{
    .{
        .func = RedBlackTree.insert,
        .fmt = "insert {}, {} -> !",
        .callbacks = .{
            .{ .param_idx = 2, .callback = insertCallback },
        },
        .generators = .{
            .{ .param_idx = 1, .generator = allocatorGenerator },
        },
    },
    .{
        .func = RedBlackTree.remove,
        .fmt = "remove {}, {} -> !{}",
        .generators = .{
            .{ .param_idx = 1, .generator = allocatorGenerator },
            .{ .param_idx = 2, .generator = removeInputGenerator },
        },
    },
});
```

The schema defines a list of operations that the fuzzer/profiler can randomly select from at runtime. Let's break down this schema (the second argument) line by line:

### 1. Function Pointer 📌

```Zig
.func = RedBlackTree.insert,
```

The `.func` field is a function pointer to the function that this *operation config* (`op_cfg` in the code) defines. The `Fuzzer` and `Profiler` struct factory functions will use Zig's comptime features to inspect this function's signature and build a wrapper function with a standardized signature `fn (*DStruct, std.Random) ErrorUnion!void` that handles generating arguments and calling the function at runtime.

> It is expected that the first argument of the function assigned to this field is a pointer to the data structure passed as the first argument to the `Fuzzer` or `Profiler` factory function.

### 2. Log Fmt String 📝

```Zig
.fmt = "insert {}, {} -> !",
```

- The `.fmt` field is a string that describes how the logger should format the function call result for a given step. The leading characters up until the first space (`insert` in this example) indicate the name that will be used for the function in the log output.

- The comma separated curly brackets indicate how to format the function's generated arguments and follow the standard Zig fmt string syntax (ie `{s}` for string, `{x}` for hex). An argument format specifier is required for each input to the function with the exception of the first argument (the pointer to the data structure).

- Finally, the `->` precedes the return value specifier, a `!` indicates an error can be returned, and there may be another pair of curly brackets at the end (ie `!{}`) to specify how to format the return value, if present. The return value format specifier can be omitted (as seen above) if the return value is void.

### 3. Callbacks 🔁

```Zig
.callbacks = .{
    .{ .param_idx = 2, .callback = insertCallback },
},
```

The `.callbacks` field is optional, and contains a list of structs that always contain two values.
- The first is `.param_idx`, the index of the argument that the callback is for.
- The second is `.callback`, a function pointer to the callback.

> The signature of the callback function must be `fn (T) void` where `T` is the same type as the argument identified by `.param_idx` of the function assigned to `.func` seen above. There can be one callback per function argument.

### 4. Generators 🎲

```Zig
.generators = .{
    .{ .param_idx = 1, .generator = allocatorGenerator },
},
```

The `.generators` field is optional, and like the `.callbacks` field seen above, it has a list of structs that always contain two fields.
- The first is `.param_idx`, which identifies the argument that the generator is for.
- The second is `.generator`, which is a function pointer that will be used to provide inputs for the parameter identified by `.param_idx`.

> The signature of the generator must be `fn () T` where `T` is the same type as the argument identified by `.param_idx` of the function assigned to `.func` seen above. There can only be one generator per argument.

### More Complex Behavior 💡

The `.callback` and `.generator` features can be paired with global state to implement behavior such as storing a copy of inputs to the data structure on insert using a callback, and then pulling from that list in a generator for removal so that semantically valid removal operations can be performed. The intent is for this abstraction to be generic enough to serve any future data structure's needs, but time will tell if this turns out to be sufficient.

### Fuzzer Invariant Validator ✔️

The final piece that a `Fuzzer` needs is an invariant validator function. This is a function that has the signature `fn (*DStruct) bool` that walks the full state of the data structure and checks/asserts any invariants, then finally returns true if the state is valid, or false if any invariant violations were detected. This function will be called after each *operation* the fuzzer executes. This type of fuzzing is incredibly powerful and efficiently roots out bugs with perfect replicability.

> It is recommended to use this validator function to log the reasoning for failure to ease debugging.

### Command Line Args 💻

After the schema is defined, the fuzzer and profiler implementations should parse their command line arguments. Typically this includes the number of iterations (`-i` flag) to fuzz/profile, the log file path (`-o` flag), and the seed for rng (`-s` flag). Here is an example implementation:

```Zig
var iterations: u64 = 0;
var log_path: []const u8 = "fuzz.log";
var seed: u64 = 0;

const allocator = dbg_alloc.allocator();
var argsIter = try std.process.ArgIterator.initWithAllocator(allocator);

const base_10 = 10;
while (argsIter.next()) |arg| {
    if (std.mem.eql(u8, arg, "-i")) {
        if (argsIter.next()) |iters| {
            iterations = try std.fmt.parseInt(u64, iters, base_10);
        }
    } else if (std.mem.eql(u8, arg, "-o")) {
        if (argsIter.next()) |path| {
            log_path = path;
        }
    } else if (std.mem.eql(u8, arg, "-s")) {
        if (argsIter.next()) |s| {
            seed = try std.fmt.parseInt(u64, s, base_10);
        }
    } else continue;
}
```

### Stepping 👣

Lastly, the fuzzer and profiler implementations will simply need to loop for the number of iterations specified by the command line arguments and inside this loop, call `.step()`. Internally, step will select a random *operation* from the *op table* and call its wrapper that was generated at comptime, and the wrapper will handle the rest as described above. Here's an example:

```Zig
for (0..iterations) |_| {
    fuzzer.step() catch |err| {
        switch (err) {
            error.NotFound => continue,
            else => return err,
        }
    };
}
```

> `.step()` aggregates all of the errors that can be returned by the fuzzer/profiler as well as the functions being fuzzed/profiled and bubbles them up. This allows for specialized error handling, as seen in the example above.

### Compiling the Code 🛠️

A build.zig for a data structure typically will contain what's needed to build both the fuzzer and the profiler, depending on which flag is passed. Either `Dfuzz=true` or `Dprof=true` (or both) is required.

### Under the Hood ⚙️

The `Fuzzer` and `Profiler` struct factory functions use the same underlying schema to initialize their *op tables* so your implementations will look nearly identical in practice. What happens under the hood is that the function signatures passed in *operation configs* are inspected, and there is comptime code that branches based on the function signatures such that code for a specialized wrapper function is emitted that will handle generating all arguments to a function, calling any callbacks, calling the function, and logging the result, plus snapshotting hardware performance counters in the case of profiling. For numerical arguments, a random number generator can be provided and a generator can be omitted from the schema.
