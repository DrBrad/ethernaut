use std::any::Any;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::time::Duration;
use gtk::prelude::*;
use gtk::{gdk, glib, Builder, Button, Container, CssProvider, Paned, StyleContext};
use gtk::glib::ControlFlow::Continue;
use pcap::devices::Device;
use crate::pcaps::CaptureService;
use crate::ui::application::OApplication;
use crate::ui::activity::inter::activity::Activity;
use crate::ui::fragment::inter::fragment::Fragment;
use crate::ui::fragment::main_fragment::MainFragment;

#[derive(Clone)]
pub struct MainActivity {
    app: OApplication,
    root: Option<Container>,
    capture_service: CaptureService
}

impl MainActivity {

    pub fn new(app: OApplication, device: &Device) -> Self {

        Self {
            app,
            root: None,
            capture_service: CaptureService::new(device)
        }
    }

    pub fn open_sidebar(&self, mut fragment: Box<dyn Fragment>) {
        let root = self.root.as_ref().unwrap().downcast_ref::<Paned>().unwrap();

        match root.child2() {
            Some(child) => {
                root.remove(&child);
            }
            None => {}
        }

        let content = fragment.on_create();
        root.add(content);
        root.set_child_shrink(content, false);
    }

    pub fn close_sidebar(&self) {
        let root = self.root.as_ref().unwrap().downcast_ref::<Paned>().unwrap();

        match root.child2() {
            Some(child) => {
                root.remove(&child);
            }
            None => {}
        }
    }
}

impl Activity for MainActivity {

    fn get_name(&self) -> String {
        "main_activity".to_string()
    }

    fn get_title(&self) -> String {
        "MainActivity".to_string()
    }

    fn on_create(&mut self) -> &Container {
        let builder = Builder::from_file("res/ui/gtk3/main-activity.ui");

        let provider = CssProvider::new();
        provider.load_from_path("res/ui/gtk3/main-activity.css").expect("Failed to load CSS file.");

        StyleContext::add_provider_for_screen(
            &gdk::Screen::default().expect("Failed to get default screen."),
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );

        let mut root: Paned = builder
            .object("window_layout")
            .expect("Couldn't find 'window_layout' in main-activity.ui");
        self.root = Some(root.clone().upcast());



        let mut main_fragment = MainFragment::new(self.dyn_clone());
        let content = main_fragment.on_create();
        root.add(content);
        root.set_child_shrink(content, false);
        root.set_child_resize(content, true);



        let (tx, rx) = channel();
        self.capture_service.set_tx(tx);


        let titlebar = self.app.get_titlebar().unwrap();
        let menu_buttons = Arc::new(self.app.get_child_by_name(&titlebar, "navigation_menu_1").unwrap());
        menu_buttons.show();

        let app_buttons = Arc::new(self.app.get_child_by_name(&titlebar, "app_buttons").unwrap());
        app_buttons.show();
        let stop_button = Arc::new(self.app.get_child_by_name(&app_buttons, "stop_button").unwrap());
        let start_button = self.app.get_child_by_name(&app_buttons, "start_button").unwrap();

        if let Some(start_button) = start_button.downcast_ref::<Button>() {
            let app_buttons = app_buttons.clone();
            let stop_button_clone = stop_button.clone();
            let main_fragment = main_fragment.clone();

            let packet_service = self.capture_service.clone();
            start_button.connect_clicked(move |_| {
                app_buttons.style_context().add_class("running");
                stop_button_clone.show();

                println!("Start button clicked!");
                main_fragment.get_packet_adapter().unwrap().clear();
                packet_service.start();
            });
        }

        if let Some(stop_button) = stop_button.downcast_ref::<Button>() {
            let app_buttons = app_buttons.clone();
            let stop_button_clone = stop_button.clone();

            let packet_service = self.capture_service.clone();
            stop_button.connect_clicked(move |_| {
                app_buttons.style_context().remove_class("running");
                stop_button_clone.hide();

                println!("Stop button clicked!");
                packet_service.stop();
            });
        }




        let _self = self.clone();
        glib::timeout_add_local(Duration::from_millis(10), move || {
            let main_fragment = main_fragment.clone();
            match rx.try_recv() {
                Ok(packet) => {
                    main_fragment.get_packet_adapter().unwrap().add(packet);
                }
                _ => {
                }
            }
            Continue
        });

        &self.root.as_ref().unwrap().upcast_ref()
    }

    fn on_resume(&self) {
        todo!()
    }

    fn on_pause(&self) {
        todo!()
    }

    fn on_destroy(&self) {
        todo!()
    }

    fn get_application(&self) -> &OApplication {
        &self.app
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn dyn_clone(&self) -> Box<dyn Activity> {
        Box::new(self.clone())
    }
}


