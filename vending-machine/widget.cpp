#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::enableButton()
{
    if(money < 100) ui->pbCoffee->setEnabled(false);
    else ui->pbCoffee->setEnabled(true);

    if(money < 150) ui->pbTea->setEnabled(false);
    else ui->pbTea->setEnabled(true);

    if(money < 200) ui->pbMilk->setEnabled(false);
    else ui->pbMilk->setEnabled(true);
}

void Widget::changeMoney(int diff)
{
    money += diff;
    ui->lcdNumber->display(money);
    enableButton();
}

void Widget::on_pb10_clicked()
{
    changeMoney(10);
}


void Widget::on_pb100_clicked()
{
    changeMoney(100);
}


void Widget::on_pb50_clicked()
{
    changeMoney(50);
}


void Widget::on_pb500_clicked()
{
    changeMoney(500);
}


void Widget::on_pbCoffee_clicked()
{
    changeMoney(-100);
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-200);
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pbReset_clicked()
{
    int cur = money;
    int coin[4] = {0, 0, 0, 0};
    int price[4] = {500, 100, 50, 10};

    for(int i = 0; i < 4; i++)
    {
        coin[i] = cur / price[i];
        cur = cur % price[i];
    }

    char msg[100];
    sprintf(msg, "500won: %d개\n100won: %d개\n50won: %d개\n10won: %d개",coin[0], coin[1], coin[2], coin[3]);

    QMessageBox mb;
    mb.information(this, "changes", msg);

    changeMoney(-money);
}

