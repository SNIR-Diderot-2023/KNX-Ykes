from Listener import Listener
import time


def main():
    listener = Listener()

    listener.SetPort("/dev/pts/1")

    print(listener.Start())

    return


# get one frame and print it
# from ListenerPlus import Listener, KnxFrame
# import time


# def main():
#     listener = Listener()

#     listener.SetPort("/dev/pts/1")

#     listener.Start()

#     yey: int = 0
#     while not yey:
#         yey = listener.size()

#     print(listener.getData().debug())

#     listener.Stop()

#     del listener


if __name__ == "__main__":
    main()
