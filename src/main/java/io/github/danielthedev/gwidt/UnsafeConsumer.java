package io.github.danielthedev.gwidt;

public interface UnsafeConsumer<T> {

    void accept(T value) throws Exception;

}
