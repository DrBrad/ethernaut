mod application;
mod pcap;

use std::process::exit;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Receiver, RecvError};
use std::thread;
use std::time::Duration;
use ::pcap::{Capture, Device};
use gtk::prelude::*;
use gtk::{Application, Builder, gio, CssProvider, StyleContext, gdk, ApplicationWindow, ListBox, ListBoxRow, Label, Orientation, ScrolledWindow, Image, ProgressBar, TreeView, ListStore, CellRendererText, TreeViewColumn, HeaderBar, Toolbar, Button, glib};
use gtk::gdk::{EventButton, EventMask};
use gtk::gio::spawn_blocking;
use gtk::glib::ControlFlow::Continue;
use gtk::glib::{idle_add, Propagation};
use gtk::glib::UnicodeBreakType::Contingent;
use crate::application::{init_titlebar, create_row, init_actions};
use crate::pcap::packet_capture;

//let (tx, rx) = channel();
/*
thread_local!(
    static GLOBAL RefCell<Option<(UiModel, mpsc::Receiver<String>)>> = RefCell::new(None);
);
*/

fn main() {
    let app = Application::new(Some("com.omniscient.rust"), Default::default());

    app.connect_activate(|app| {
        let builder = Builder::from_file("res/ui/gtk3/window.ui");

        let provider = CssProvider::new();
        provider.load_from_path("res/ui/gtk3/style.css").expect("Failed to load CSS file.");

        StyleContext::add_provider_for_screen(
            &gdk::Screen::default().expect("Failed to get default screen."),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );

        let window: ApplicationWindow = builder
            .object("MainWindow")
            .expect("Failed to get the 'MainWindow' from window.ui");

        window.set_application(Some(app));
        window.connect_destroy(|_| exit(0));
        //window.set_decorated(false);
        window.set_border_width(1);

        let titlebar_builder = init_titlebar(&window, app);





        /*
        let svg_data = include_bytes!("../res/ic_launcher.svg");
        let loader = PixbufLoader::with_type("svg").expect("Failed to create SVG loader");
        loader.write(svg_data).expect("Failed to load SVG data");
        loader.close().expect("Failed to close SVG loader");
        let icon_pixbuf = loader.pixbuf().expect("Failed to get Pixbuf from SVG");

        window.set_icon(Some(&icon_pixbuf));
        */
        //window.set_icon_from_file("res/images/ic_launcher.svg").expect("Failed to load icon");

        //let window = Window::new(WindowType::Toplevel);
        //window.set_title("Omniscient");




        let list_box = ListBox::new();
        //for i in 0..100 {
        //list_box.add(&create_row());
        //}
        /*
        list_box.add(&create_row(PacketType::Tcp));
        list_box.add(&create_row(PacketType::Udp));
        list_box.add(&create_row(PacketType::Icmp));
        list_box.add(&create_row(PacketType::Gre));*/

        let list_scroll_layout: ScrolledWindow = builder
            .object("list_scroll_layout")
            .expect("Couldn't find 'list_scroll_layout' in window.ui");

        list_scroll_layout.add(&list_box);
        list_box.show_all();



        let (tx, rx) = channel();

        let tx = Arc::new(Mutex::new(tx));


        let start_button: Button = titlebar_builder
            .object("start_button")
            .expect("Couldn't find 'start_button' in titlebar-ui.xml");

        start_button.connect_clicked(move |_| {
            println!("Start button clicked!");
            packet_capture(tx.clone());
            //packet_capture(&list_box);

            //let list_box_clone = Arc::new(Mutex::new(list_box.clone()));

            /*
            let tx = tx.clone();
            //spawn_blocking(move || {
            thread::spawn(move || {
                let devices = Device::list().expect("Failed to get device list");

                let device = devices.into_iter().find(|d| d.name.contains("wlp2s0"))
                    .expect("No suitable device found");

                println!("Listening on device: {}", device.name);

                let mut cap = Capture::from_device(device)
                    .expect("Failed to open device")
                    .promisc(true)
                    .immediate_mode(true)
                    .open()
                    .expect("Failed to start capture");

                while let Ok(packet) = cap.next_packet() {
                    println!("Captured packet: {:?} ({} bytes)", packet, packet.data.len());

                    if packet.data.len() > 20 { // Ensure it's at least an IPv4 header
                        let protocol = packet.data[23]; // Byte 9 in IPv4 header

                        match protocol {
                            0x01 => println!("Captured an ICMP Packet"),
                            0x06 => println!("Captured a TCP Packet"),
                            0x11 => println!("Captured a UDP Packet"),
                            0x2F => println!("Captured a GRE Packet"),
                            _    => println!("Captured an unknown protocol: {}", protocol),
                        }

                        tx.send(PacketType::Gre).unwrap()
                        //list_box_clone.lock().unwrap().add(&create_row(PacketType::Gre));
                    }
                }
            });
            */
        });


        //let list_box = Arc::new(Mutex::new(list_box.clone()));

        //let (tx, rx) = channel();

        /*
        thread::spawn(move || {
            //while let Ok(message) = rx.recv() {
                // Safely update the ListBox in the main thread
                let list_box = list_box.lock().unwrap();
                let label = Label::new(Some("asdasd"));//message));
                list_box.add(&label);
                list_box.show_all();
            //}
        });*/









        /*
        let builder = Builder::from_file("res/ui/omniscient-ui.xml");
        let menubar: gio::Menu = builder
            .object("main_window_menu")
            .expect("Couldn't find 'main_window_menu' in omniscient-ui.xml");

        app.set_menubar(Some(&menubar));
        */

        init_actions(&app, &window);

        window.show_all();




        /*
        loop {
            match rx.recv() {
                Ok(packet) => {
                    list_box.add(&create_row(packet));
                }
                _ => {}
            }
        }
        */

        /*
        thread::spawn(|| {
            let devices = Device::list().expect("Failed to get device list");

            let device = devices.into_iter().find(|d| d.name.contains("wlp2s0"))
                .expect("No suitable device found");

            println!("Listening on device: {}", device.name);

            let mut cap = Capture::from_device(device)
                .expect("Failed to open device")
                .promisc(true)
                .immediate_mode(true)
                .open()
                .expect("Failed to start capture");

            while let Ok(packet) = cap.next_packet() {
                println!("Captured packet: {:?} ({} bytes)", packet, packet.data.len());

                if packet.data.len() > 20 { // Ensure it's at least an IPv4 header
                    let protocol = packet.data[23]; // Byte 9 in IPv4 header

                    match protocol {
                        0x01 => println!("Captured an ICMP Packet"),
                        0x06 => println!("Captured a TCP Packet"),
                        0x11 => println!("Captured a UDP Packet"),
                        0x2F => println!("Captured a GRE Packet"),
                        _    => println!("Captured an unknown protocol: {}", protocol),
                    }
                }
            }
        });
        */

        let mut i =0;

        glib::timeout_add_local(Duration::from_millis(100), move || {
            /*
            if let Ok(message) = rx.try_recv() {
                match message {
                    UpdateMessage::AddRow(packet_type) => {
                        // Update the UI in the main thread
                        let row = create_row(packet_type);
                        list_box.add(&row);
                        window.show_all(); // Make sure the window is refreshed
                    }
                }
            }
            */

            match rx.try_recv() {
                Ok(packet) => {
                    i += 1;
                    let row = create_row(i, packet);
                    list_box.add(&row);
                    row.show_all();
                }
                _ => {
                }
            }



            Continue//(true) // Keep the timeout running
        });


    });

    app.run();
}






pub enum PacketType {
    Tcp,
    Udp,
    Icmp,
    Gre
}



